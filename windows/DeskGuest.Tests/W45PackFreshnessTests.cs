using System.Text.Json;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 45 Lane B — the Item 4 parenthetical: whole-chain
/// rollback to an older GENUINE compliance pack.
///
/// Assessment (stated plainly, per brief): the pack leg's
/// freshness rested on NOTHING before W45. VerifyStoredPack
/// judged the chain alone, the chain is a data-dir file, and a
/// truncated-to-older chain carries only genuine records — every
/// W37 leg (hash, scheme, position-bound signature under the
/// archived/current pin) passes for the older pack on it. The
/// staged-rollback shape therefore applied verbatim. It closes
/// with the SAME discipline as pointers because the pack anchor
/// already writes through the same PointerAuditAnchor machinery:
/// one install-root marker over the one chain. A keyed Compile
/// advances the marker to its landing position; VerifyStoredPack
/// judges the chain against the marker (freshness leg). These
/// tests pin that outcome.</summary>
public class W45PackFreshnessTests
{
    private sealed class KeyedRig : IDisposable
    {
        public required Rmm05Tests.Rig Vuln { get; init; }
        public required ComplianceService Service { get; init; }
        public required PointerSigningCustody Custody { get; init; }
        public required string InstallRoot { get; init; }
        public required string DataDir { get; init; }
        public void Dispose()
        {
            try { Directory.Delete(InstallRoot, recursive: true); } catch { }
            try { Directory.Delete(DataDir, recursive: true); } catch { }
        }
    }

    private static KeyedRig NewKeyedRig()
    {
        var v = Rmm05Tests.NewRig();
        var install = TestUtil.TempDir();
        var data = TestUtil.TempDir();
        var custody = new PointerSigningCustody(install, data);
        custody.EnsureKeyForInstall();
        var svc = new ComplianceService(v.Audit, v.Policies, v.Inventory,
            v.Patches.Service, v.Service, v.Clock.UtcNow, custody);
        svc.ContentPacks.SeedDefaults();
        return new KeyedRig { Vuln = v, Service = svc, Custody = custody, InstallRoot = install, DataDir = data };
    }

    private static void AddDevice(KeyedRig rig, ComplianceService svc)
    {
        rig.Vuln.Inventory.ApplyBaseline(
            Rmm05Tests.Record("dev1", software: new[] { ("Google Chrome", "130.0") }), Rmm09Tests.T0);
        svc.RegisterSecurityState(new DeviceSecurityState(
            "dev1", "scope1", true, true, true, Rmm09Tests.T0), "monitor");
    }

    [Fact]
    public void WholeChainRollback_ToOlderGenuinePack_RefusedAtFreshnessLeg()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);

        // First genuine pack: its keyed compile advances the
        // install-root marker to its landing position.
        var pack1 = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var countAtPack1 = rig.Vuln.Audit.Entries.Count;
        var marker1 = Assert.Single(PointerAnchorMarker.ReadAll(rig.InstallRoot));
        Assert.Equal(countAtPack1, marker1.ChainEntries);
        Assert.Equal($"advanced:chain_entries={countAtPack1}", rig.Service.AnchorMarkerState);

        // Second genuine pack: the marker advances past pack1.
        var pack2 = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.NotEqual(pack1.PackId, pack2.PackId);
        var countAtPack2 = rig.Vuln.Audit.Entries.Count;
        Assert.True(countAtPack2 > countAtPack1);
        Assert.Equal(countAtPack2, Assert.Single(PointerAnchorMarker.ReadAll(rig.InstallRoot)).ChainEntries);

        // Control: on the full (grown) chain the older pack still
        // verifies — growth past the marker is accepted, the
        // prefix binds.
        Assert.True(rig.Service.VerifyStoredPack(pack1.PackId, out var okReason), okReason);

        // Attack: whole-chain rollback — truncate the chain to
        // exactly pack1's position (every remaining byte genuine)
        // and present pack1 after a simulated restart. Every W37
        // leg passes on this chain; only freshness can refuse.
        var truncated = new ChainedAuditLog();
        var prefixJson = JsonSerializer.Serialize(rig.Vuln.Audit.Entries.Take(countAtPack1).ToList());
        Assert.True(truncated.ImportEntriesJson(prefixJson).Ok);
        var svc2 = new ComplianceService(truncated, rig.Vuln.Policies, rig.Vuln.Inventory,
            rig.Vuln.Patches.Service, rig.Vuln.Service, rig.Vuln.Clock.UtcNow, rig.Custody);
        svc2.RestoreStoredPack(pack1);
        Assert.False(svc2.VerifyStoredPack(pack1.PackId, out var reason));
        Assert.Contains("freshness leg (W45)", reason);
        Assert.Contains("FEWER than", reason);
    }

    [Fact]
    public void PackMarkerAdvanceFailure_RefusesCompileByName_NoPackStored()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        // Sabotage ONLY the marker's landing: a directory squatting
        // on the marker path makes the marker write fail while the
        // chain appends and the signing keep working.
        Directory.CreateDirectory(PointerAnchorMarker.MarkerPath(rig.InstallRoot));
        var result = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin");
        Assert.False(result.Ok);
        Assert.Contains("anchor marker advance FAILED", result.Reason);
        Assert.Empty(rig.Service.PackHistory);
        Assert.StartsWith("anchor marker advance FAILED", rig.Service.AnchorMarkerState);
    }
}
