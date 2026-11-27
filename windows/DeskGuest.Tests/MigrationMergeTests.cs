using DeskGuest.Shared.Migration;

namespace DeskGuest.Tests;

/// <summary>R1 Defect 2 pins (2026-11-26): the migration MERGE
/// mode. The R1 installer seeded the new DeskGuest tree (identity,
/// terms receipt, role, update slots) before the first Core start,
/// and the pre-fix migration treated any populated new tree as
/// "already migrated" — the owner's legacy state (pairings, trust,
/// history) silently never carried. These fixtures reproduce the
/// two owed cases from BUILD-LOG #155 Addendum 3: an
/// installer-seeded tree merges with its seed content untouched,
/// and a genuinely populated tree is never overwritten — with the
/// marker's counts reconciling against the legacy total in
/// both.</summary>
public class MigrationMergeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "dg-merge-" + Guid.NewGuid().ToString("N"));
    private string Legacy => Path.Combine(_root, "legacy-data");
    private string New => Path.Combine(_root, "new-data");

    public MigrationMergeTests()
    {
        // Legacy tree: owner state + a conflict + excluded machinery.
        Directory.CreateDirectory(Path.Combine(Legacy, "hub"));
        Directory.CreateDirectory(Path.Combine(Legacy, "chat"));
        Directory.CreateDirectory(Path.Combine(Legacy, "updates", "slots", "A"));
        Directory.CreateDirectory(Path.Combine(Legacy, "staging"));
        File.WriteAllText(Path.Combine(Legacy, "pairings.json"), "{\"pairs\":[\"legacy\"]}");
        File.WriteAllText(Path.Combine(Legacy, "data-flows.json"), "legacy-flows");
        File.WriteAllText(Path.Combine(Legacy, "hub", "hub.db"), "legacy-hub");
        File.WriteAllText(Path.Combine(Legacy, "chat", "thread-1.json"), "legacy-chat");
        File.WriteAllText(Path.Combine(Legacy, "core-identity.key"), "LEGACY-KEY");
        File.WriteAllText(Path.Combine(Legacy, "updates", "slots", "A", "DeskGuestCore.exe"), "legacy-slot-binary");
        File.WriteAllText(Path.Combine(Legacy, "updates", "pointer.json"), "legacy-pointer");
        File.WriteAllText(Path.Combine(Legacy, "staging", "blob.bin"), "transient");
        File.WriteAllText(Path.Combine(Legacy, "heartbeat.json"), "stale-liveness");
        File.WriteAllText(Path.Combine(Legacy, "run-marker.json"), "stale-marker");
        File.WriteAllText(Path.Combine(Legacy, "run-marker.stale-20260101.json"), "stale-marker-2");
        File.WriteAllText(Path.Combine(Legacy, "core-instance.lock"), "lock");
        // Legacy total: 12 files. Excluded by rule: updates x2,
        // staging x1, heartbeat, run-marker x2, core-instance.lock
        // = 7. Carried-or-present: 5.
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private void SeedNewTree()
    {
        Directory.CreateDirectory(Path.Combine(New, "updates", "slots", "A"));
        File.WriteAllText(Path.Combine(New, "core-identity.key"), "NEW-KEY");
        File.WriteAllText(Path.Combine(New, "terms-acceptance.json"), "{\"binding\":false}");
        File.WriteAllText(Path.Combine(New, "updates", "slots", "A", "DeskGuestCore.exe"), "new-slot-binary");
    }

    [Fact]
    public void InstallerSeededTree_Merges_SeedUntouched_CountsReconcile()
    {
        SeedNewTree();
        var r = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Merged, r.Outcome);
        // Carried: pairings, data-flows, hub.db, chat thread = 4.
        // Already present (conflict, new tree wins): core-identity.key = 1.
        // Excluded: 7. Total reconciles: 4 + 1 + 7 = 12.
        Assert.Equal(4, r.FilesCopied);
        Assert.Equal(1, r.FilesAlreadyPresent);
        Assert.Equal(7, r.FilesExcluded);
        Assert.Equal(12, r.FilesCopied + r.FilesAlreadyPresent + r.FilesExcluded);
        // Seed content untouched, byte for byte.
        Assert.Equal("NEW-KEY", File.ReadAllText(Path.Combine(New, "core-identity.key")));
        Assert.Equal("new-slot-binary", File.ReadAllText(Path.Combine(New, "updates", "slots", "A", "DeskGuestCore.exe")));
        Assert.Equal("{\"binding\":false}", File.ReadAllText(Path.Combine(New, "terms-acceptance.json")));
        // Owner state carried.
        Assert.Equal("{\"pairs\":[\"legacy\"]}", File.ReadAllText(Path.Combine(New, "pairings.json")));
        Assert.Equal("legacy-flows", File.ReadAllText(Path.Combine(New, "data-flows.json")));
        Assert.Equal("legacy-hub", File.ReadAllText(Path.Combine(New, "hub", "hub.db")));
        Assert.Equal("legacy-chat", File.ReadAllText(Path.Combine(New, "chat", "thread-1.json")));
        // Excluded machinery did NOT arrive.
        Assert.False(File.Exists(Path.Combine(New, "updates", "pointer.json")));
        Assert.False(File.Exists(Path.Combine(New, "staging", "blob.bin")));
        Assert.False(File.Exists(Path.Combine(New, "heartbeat.json")));
        Assert.False(File.Exists(Path.Combine(New, "run-marker.json")));
        Assert.False(File.Exists(Path.Combine(New, "core-instance.lock")));
        // Marker records the reconciliation.
        var marker = File.ReadAllText(Path.Combine(New, LegacyStateMigration.MarkerFileName));
        Assert.Contains("\"mode\": \"merge\"", marker);
        Assert.Contains("\"filesCopied\": 4", marker);
        Assert.Contains("\"filesAlreadyPresent\": 1", marker);
        Assert.Contains("\"filesExcluded\": 7", marker);
        Assert.Contains("\"legacyFilesTotal\": 12", marker);
        // Legacy tree intact (copy, never move).
        Assert.Equal("LEGACY-KEY", File.ReadAllText(Path.Combine(Legacy, "core-identity.key")));
    }

    [Fact]
    public void MergedTree_SecondRun_IsAlreadyMigrated_NoOp()
    {
        SeedNewTree();
        var first = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Merged, first.Outcome);
        File.WriteAllText(Path.Combine(New, "pairings.json"), "{\"pairs\":[\"edited\"]}");
        var second = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.AlreadyMigrated, second.Outcome);
        Assert.Equal(0, second.FilesCopied);
        Assert.Equal("{\"pairs\":[\"edited\"]}", File.ReadAllText(Path.Combine(New, "pairings.json")));
    }

    [Fact]
    public void FreshTree_CopyMode_ExclusionsStillApply()
    {
        var r = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Migrated, r.Outcome);
        // No conflicts on a fresh tree: 5 carried, 7 excluded.
        Assert.Equal(5, r.FilesCopied);
        Assert.Equal(0, r.FilesAlreadyPresent);
        Assert.Equal(7, r.FilesExcluded);
        Assert.Equal("LEGACY-KEY", File.ReadAllText(Path.Combine(New, "core-identity.key")));
        Assert.False(File.Exists(Path.Combine(New, "updates", "pointer.json")));
        Assert.False(File.Exists(Path.Combine(New, "heartbeat.json")));
        var marker = File.ReadAllText(Path.Combine(New, LegacyStateMigration.MarkerFileName));
        Assert.Contains("\"mode\": \"copy\"", marker);
    }

    [Theory]
    [InlineData("updates/pointer.json", true)]
    [InlineData("staging/blob.bin", true)]
    [InlineData("heartbeat.json", true)]
    [InlineData("run-marker.json", true)]
    [InlineData("run-marker.stale-20260101.json", true)]
    [InlineData("core-instance.lock", true)]
    [InlineData("deskguest-migration.json", true)]
    [InlineData("pairings.json", false)]
    [InlineData("hub/hub.db", false)]
    [InlineData("data/updates-notes.txt", false)]
    public void ExclusionRule_ByRelativePath(string relativePath, bool expected) =>
        Assert.Equal(expected, LegacyStateMigration.IsExcluded(relativePath));
}
