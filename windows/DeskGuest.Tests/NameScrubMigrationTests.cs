using DeskGuest.Shared.Migration;
using Xunit;

namespace DeskGuest.Tests;

/// <summary>Item (20) rename carry-over pins: the one-time legacy
/// state migration (LegacyStateMigration) — copies the legacy data
/// tree into the new DeskGuest root, loses nothing, and is
/// idempotent. Fixtures are synthetic directory trees; the legacy
/// root in these tests is a stand-in path, not the real one.</summary>
public class NameScrubMigrationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "dg-mig-" + Guid.NewGuid().ToString("N"));
    private string Legacy => Path.Combine(_root, "legacy-data");
    private string New => Path.Combine(_root, "new-data");

    public NameScrubMigrationTests()
    {
        Directory.CreateDirectory(Path.Combine(Legacy, "data", "hub"));
        Directory.CreateDirectory(Path.Combine(Legacy, "trust"));
        Directory.CreateDirectory(Path.Combine(Legacy, "empty-dir"));
        File.WriteAllText(Path.Combine(Legacy, "data", "pairings.json"), "{\"pairs\":[]}");
        File.WriteAllText(Path.Combine(Legacy, "data", "hub", "hub.db"), "hub-state");
        File.WriteAllText(Path.Combine(Legacy, "trust", "agent-trust-record.json"), "{}");
        File.WriteAllText(Path.Combine(Legacy, "core-identity.key"), "key-material");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void Migrates_LegacyTree_NothingLost()
    {
        var r = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Migrated, r.Outcome);
        Assert.Equal(4, r.FilesCopied);
        Assert.Equal("{\"pairs\":[]}", File.ReadAllText(Path.Combine(New, "data", "pairings.json")));
        Assert.Equal("hub-state", File.ReadAllText(Path.Combine(New, "data", "hub", "hub.db")));
        Assert.Equal("{}", File.ReadAllText(Path.Combine(New, "trust", "agent-trust-record.json")));
        Assert.Equal("key-material", File.ReadAllText(Path.Combine(New, "core-identity.key")));
        Assert.True(Directory.Exists(Path.Combine(New, "empty-dir")));
        Assert.True(File.Exists(Path.Combine(New, LegacyStateMigration.MarkerFileName)));
        // Copy, not move: the legacy tree is intact for rollback.
        Assert.True(File.Exists(Path.Combine(Legacy, "core-identity.key")));
    }

    [Fact]
    public void SecondRun_IsNoOp_Idempotent()
    {
        var first = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Migrated, first.Outcome);
        File.WriteAllText(Path.Combine(New, "data", "pairings.json"), "{\"pairs\":[\"changed\"]}");
        var second = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.AlreadyMigrated, second.Outcome);
        Assert.Equal(0, second.FilesCopied);
        // The post-migration edit is NOT overwritten by a re-run.
        Assert.Equal("{\"pairs\":[\"changed\"]}", File.ReadAllText(Path.Combine(New, "data", "pairings.json")));
    }

    [Fact]
    public void ExistingNewTree_Merges_NeverOverwrites()
    {
        // R1 fix (2026-11-26): the pre-fix contract left a populated
        // new tree untouched, which the R1 installer defeated by
        // seeding the tree before first start — the carry-over
        // silently never ran. A populated tree now MERGES: the
        // existing file is never overwritten, legacy-only files
        // are carried, and the marker records the reconciliation.
        // Full merge pins live in MigrationMergeTests.
        Directory.CreateDirectory(New);
        File.WriteAllText(Path.Combine(New, "own.txt"), "mine");
        var r = LegacyStateMigration.EnsureMigrated(New, Legacy);
        Assert.Equal(LegacyStateMigration.Outcome.Merged, r.Outcome);
        Assert.Equal("mine", File.ReadAllText(Path.Combine(New, "own.txt")));
        Assert.True(File.Exists(Path.Combine(New, "core-identity.key")));
        Assert.True(File.Exists(Path.Combine(New, LegacyStateMigration.MarkerFileName)));
    }

    [Fact]
    public void NoLegacyTree_IsCleanNoOp()
    {
        var r = LegacyStateMigration.EnsureMigrated(New, Path.Combine(_root, "does-not-exist"));
        Assert.Equal(LegacyStateMigration.Outcome.NoLegacyTree, r.Outcome);
        Assert.False(Directory.Exists(New));
    }
}
