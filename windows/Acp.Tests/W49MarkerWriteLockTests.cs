using System.Collections.Concurrent;
using Acp.Shared.Enterprise;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 49 Lane B — marker-guard ATOMICITY in the Write
/// primitive: the DeepSeek round-11 Item 2 fix. Round 11 ruled
/// the W47 construction inadequate on two shapes, both one root
/// (the guard's read-check-write was not atomic, and it did not
/// cover the launcher's write at all):
///   (1) OUTSIDE-GATE RACE: writer A reads marker N and passes
///       the W47 guard for N+2; writer B writes N+3; A writes
///       N+2 — the marker regresses. The W47 guard sat in
///       AdvanceInstallRootMarker, whose read-check-write no
///       lock serialized against callers outside ChainGate.
///   (2) LAUNCHER TOCTOU: the launcher passes FreshnessRefusal
///       (marker N vs chain N+3), the Core advances to N+4, the
///       launcher's unguarded PointerAnchorMarker.Write lands
///       its stale N+3 — regression through the primitive.
/// The fix (PointerAnchorMarker.Write): the guard lives IN the
/// primitive, executed under an OS-level exclusive lock on the
/// lock file beside the marker (FileShare.None, held across
/// read-check-write, bounded wait, fail closed by name), with
/// the current marker re-read under the lock. The Core and the
/// launcher are separate processes, so the exclusion is the
/// kernel's, not any in-process gate's.
///
/// HARNESS EQUIVALENCE, argued plainly (the task's condition for
/// not spawning a second test process): these pins use two
/// INDEPENDENT writer stacks — separate ChainedAuditLog
/// instances, separate snapshots, NO shared ChainGate, NO
/// shared statics (the guarded Write holds no in-process state
/// at all) — sharing NOTHING but the files on disk. That is a
/// faithful equivalent of the two-process shape because the
/// mechanism under test is a kernel file lock: FileShare.None
/// exclusion is enforced per open file description by the OS,
/// identically for two threads in one process and for two
/// processes — the lock neither knows nor cares which process
/// holds it. The lock-timeout pin goes further and holds the
/// lock through a RAW FileStream, exactly the handle a foreign
/// process's guarded write would hold. What the pins do NOT
/// claim: scheduling across real process boundaries — the
/// interleaves that matter (stale snapshot vs landed later
/// write) are forced deterministically with events, which is
/// STRONGER than hoping a scheduler produces them.</summary>
public class W49MarkerWriteLockTests
{
    private static ChainedAuditLog LogWith(int count, string tag)
    {
        var log = new ChainedAuditLog();
        for (var i = 1; i <= count; i++)
            log.Append("session_open", "SYSTEM", $"{tag} entry {i}", DateTimeOffset.UtcNow);
        return log;
    }

    private static PointerAnchorMarker.Marker Marker(string dir) =>
        Assert.Single(PointerAnchorMarker.ReadAll(dir));

    private static string Head(int seed) => new string((char)('a' + seed % 26), 64);

    // ---------- the guard, in the primitive itself ----------

    [Fact]
    public void GuardInPrimitive_BackwardWrite_RefusedByName_MarkerByteUnchanged()
    {
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        // A DIRECT write through the primitive — no advance
        // operation, no gate — proposing a lower count.
        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 3, Head(3)));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("BACKWARD", ex.Message);
        // Byte-unchanged, and the lock file now lives beside the
        // marker (the custody artefact of the guarded write).
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.True(File.Exists(PointerAnchorMarker.LockPath(dir)));
        Assert.Equal(5, Marker(dir).ChainEntries);
    }

    [Fact]
    public void GuardInPrimitive_SameCountDifferentHead_Refused_IdempotentAllowed_WitnessPreservesPosition()
    {
        var dir = TestUtil.TempDir();
        var sha = new string('f', 64);
        PointerAnchorMarker.Write(dir, sha, 5, Head(5));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, sha, 5, Head(9)));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("same-count rewrite", ex.Message);
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));

        // Same count + same head is an idempotent re-write: allowed.
        PointerAnchorMarker.Write(dir, sha, 5, Head(5));
        Assert.Equal(5, Marker(dir).ChainEntries);

        // A witness-only write (no count proposed — the
        // UpdateManager / updates-root shape) updates the pointer
        // hash but must NOT drop the regression fields.
        var sha2 = new string('e', 64);
        PointerAnchorMarker.Write(dir, sha2, null, null);
        var after = Marker(dir);
        Assert.Equal(sha2, after.PointerSha256);
        Assert.Equal(5, after.ChainEntries);
        Assert.Equal(Head(5), after.ChainHead);

        // Forward is allowed.
        PointerAnchorMarker.Write(dir, sha2, 6, Head(6));
        Assert.Equal(6, Marker(dir).ChainEntries);
    }

    // ---------- (1) DeepSeek's round-11 interleave, verbatim shape ----------

    [Fact]
    public void Round11Interleave_TwoStacksOutsideAnyGate_StaleAdvanceRefused_MarkerStaysAtLater()
    {
        var install = TestUtil.TempDir();
        // Two INDEPENDENT writer stacks: separate logs, separate
        // snapshots, no shared gate, no shared statics — only the
        // install dir on disk is shared.
        var logA = LogWith(4, "writer-A");
        var logB = LogWith(5, "writer-B");
        var snapA4 = logA.Entries;   // A's stale snapshot: N+2 over the marker's N=2
        var snapB5 = logB.Entries;   // B's later position: N+3

        // Marker stands at N=2 (B's prefix position).
        var seed = PointerAuditAnchor.AdvanceInstallRootMarker(install, logB.Entries.Take(2).ToList());
        Assert.True(seed.Ok, seed.State);
        Assert.Equal(2, Marker(install).ChainEntries);

        // Force DeepSeek's interleave deterministically: B's
        // advance LANDS first; only then is A's stale advance
        // released. Pre-W49, A's unguarded read-check-write
        // landed N+2 over B's N+3 (here: 4 over 5).
        using var bLanded = new ManualResetEventSlim(false);
        (bool Ok, string State) aResult = default;
        var threadA = new Thread(() =>
        {
            bLanded.Wait();
            aResult = PointerAuditAnchor.AdvanceInstallRootMarker(install, snapA4);
        });
        threadA.Start();
        var bResult = PointerAuditAnchor.AdvanceInstallRootMarker(install, snapB5);
        Assert.True(bResult.Ok, bResult.State);
        var bytesAfterB = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install));
        bLanded.Set();
        threadA.Join();

        // A's stale advance is REFUSED BY NAME at the primitive;
        // the marker stays at B's later position, byte-unchanged.
        Assert.False(aResult.Ok);
        Assert.Contains("monotonicity guard", aResult.State);
        Assert.Contains("BACKWARD", aResult.State);
        Assert.Equal(bytesAfterB, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install)));
        var marker = Marker(install);
        Assert.Equal(5, marker.ChainEntries);
        Assert.Equal(snapB5[^1].Hash, marker.ChainHead);
    }

    [Fact]
    public void TwoIndependentStacks_EveryStaleAdvanceRefusedByName_MarkerEndsAtMaximum()
    {
        var install = TestUtil.TempDir();
        var logB = LogWith(4, "stack-B");
        var logA = LogWith(6, "stack-A");

        // Stack B runs to completion first: marker at (4, B-head).
        for (var i = 1; i <= 4; i++)
        {
            var r = PointerAuditAnchor.AdvanceInstallRootMarker(install, logB.Entries.Take(i).ToList());
            Assert.True(r.Ok, r.State);
        }
        // Stack A — a fully independent stack whose chain diverged
        // from B's at genesis — now advances step by step. Counts
        // 1..3 are BACKWARD against the marker; count 4 is a
        // same-count rewrite to a DIFFERENT head; every one must
        // refuse BY NAME with the marker unmoved. Counts 5..6 are
        // forward and land: the marker ends at the MAXIMUM.
        var refusalStates = new List<string>();
        for (var i = 1; i <= 6; i++)
        {
            var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install));
            var r = PointerAuditAnchor.AdvanceInstallRootMarker(install, logA.Entries.Take(i).ToList());
            if (i <= 4)
            {
                Assert.False(r.Ok);
                Assert.Contains("monotonicity guard", r.State);
                Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install)));
                refusalStates.Add(r.State);
            }
            else Assert.True(r.Ok, r.State);
        }
        Assert.Contains(refusalStates, s => s.Contains("BACKWARD"));
        Assert.Contains(refusalStates, s => s.Contains("same-count rewrite"));
        var marker = Marker(install);
        Assert.Equal(6, marker.ChainEntries);
        Assert.Equal(logA.Entries[^1].Hash, marker.ChainHead);
    }

    // ---------- (2) the launcher-shape race ----------

    [Fact]
    public void LauncherShapeRace_StaleRefreshWrite_RefusedByName_MarkerStaysAtCorePosition()
    {
        var install = TestUtil.TempDir();
        var chain = LogWith(7, "chain");
        var entries = chain.Entries;

        // Marker at N=4 (Core-advanced).
        Assert.True(PointerAuditAnchor.AdvanceInstallRootMarker(install, entries.Take(4).ToList()).Ok);

        // LAUNCHER: its check runs FreshnessRefusal against the
        // chain at N+3=7 — passes (growth, prefix binds). The
        // launcher now holds a vouched snapshot at count 7 and is
        // about to refresh the marker to (7, head7) — the exact
        // Write call PointerAuditAnchor.Check makes.
        var markers = PointerAnchorMarker.ReadAll(install);
        Assert.Null(PointerAuditAnchor.FreshnessRefusal(markers, entries));

        // CORE advances meanwhile to N+4=8 (one more append).
        chain.Append("session_open", "SYSTEM", "core advance during launcher check", DateTimeOffset.UtcNow);
        var coreEntries = chain.Entries;
        Assert.True(PointerAuditAnchor.AdvanceInstallRootMarker(install, coreEntries).Ok);
        Assert.Equal(8, Marker(install).ChainEntries);
        var bytesAfterCore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install));

        // LAUNCHER's stale refresh lands now. Pre-W49 this Write
        // was unguarded and regressed the marker 8 → 7. Now the
        // primitive refuses it BY NAME and the marker is
        // byte-unchanged at the Core's position.
        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(install, null, entries.Count, entries[^1].Hash));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("BACKWARD", ex.Message);
        Assert.Equal(bytesAfterCore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install)));
        Assert.Equal(8, Marker(install).ChainEntries);
    }

    // ---------- concurrent writers: the maximum wins ----------

    [Fact]
    public void ConcurrentGuardedWrites_ManyWriters_EndAtMaximum_EveryRefusalNamed()
    {
        var dir = TestUtil.TempDir();
        const int writers = 16;
        var refusals = new ConcurrentBag<Exception>();
        var unexpected = new ConcurrentBag<Exception>();
        using var start = new ManualResetEventSlim(false);
        var tasks = new List<Task>();
        // Writers propose counts 1..16 in a fixed scrambled order,
        // all released at once: genuine contention on the OS lock,
        // no shared anything but the directory.
        foreach (var n in new[] { 7, 16, 3, 12, 1, 9, 15, 5, 11, 2, 14, 6, 10, 4, 13, 8 })
        {
            var count = n;
            tasks.Add(Task.Run(() =>
            {
                start.Wait();
                try { PointerAnchorMarker.Write(dir, null, count, Head(count)); }
                catch (PointerAnchorMarker.MarkerWriteRefusedException ex) { refusals.Add(ex); }
                catch (Exception ex) { unexpected.Add(ex); }
            }));
        }
        start.Set();
        Task.WaitAll(tasks.ToArray());

        // The ONLY tolerable failure is the named refusal; the
        // marker ends at the maximum proposed (count, head).
        Assert.Empty(unexpected);
        Assert.All(refusals, ex => Assert.Contains("monotonicity guard", ex.Message));
        var marker = Marker(dir);
        Assert.Equal(writers, marker.ChainEntries);
        Assert.Equal(Head(writers), marker.ChainHead);
        // And a late stale writer still refuses.
        Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, writers - 1, Head(writers - 1)));
    }

    // ---------- lock contention: fail closed, named, bounded ----------

    [Fact]
    public void LockHeldByRawStream_WriteFailsClosedNamed_MarkerUnchanged_ThenSucceedsAfterRelease()
    {
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        // Hold the marker lock through a RAW FileStream with
        // FileShare.None — exactly the handle a foreign PROCESS's
        // guarded write (Core or launcher) would hold. The
        // exclusion the writer meets is the kernel's, not any
        // in-process artefact.
        using (var held = new FileStream(PointerAnchorMarker.LockPath(dir),
                   FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            var ex = Assert.Throws<PointerAnchorMarker.MarkerLockTimeoutException>(
                () => PointerAnchorMarker.Write(dir, null, 6, Head(6),
                    lockTimeout: TimeSpan.FromMilliseconds(300)));
            Assert.Contains("LOCK TIMEOUT", ex.Message);
            Assert.Contains("FAILED CLOSED", ex.Message);
            // Fail closed means: marker byte-unchanged, no
            // unlocked write slipped through.
            Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
            Assert.Equal(5, Marker(dir).ChainEntries);
        }
        // Lock released: the same write lands.
        PointerAnchorMarker.Write(dir, null, 6, Head(6));
        Assert.Equal(6, Marker(dir).ChainEntries);
    }

    [Fact]
    public void LockHeld_AdvanceFailsClosedNamed_NoAdvance()
    {
        var install = TestUtil.TempDir();
        var log = LogWith(3, "lock-advance");
        Assert.True(PointerAuditAnchor.AdvanceInstallRootMarker(install, log.Entries.Take(2).ToList()).Ok);
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install));

        using (var held = new FileStream(PointerAnchorMarker.LockPath(install),
                   FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            // The advance uses the primitive's default bounded
            // wait (5s) and then fails closed BY NAME — it does
            // not write unlocked and does not wait forever.
            var (ok, state) = PointerAuditAnchor.AdvanceInstallRootMarker(install, log.Entries);
            Assert.False(ok);
            Assert.Contains("marker lock timeout", state);
            Assert.Contains("LOCK TIMEOUT", state);
            Assert.Contains("NOT advanced", state);
            Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(install)));
        }
        // After release the advance lands.
        var after = PointerAuditAnchor.AdvanceInstallRootMarker(install, log.Entries);
        Assert.True(after.Ok, after.State);
        Assert.Equal(3, Marker(install).ChainEntries);
    }
}
