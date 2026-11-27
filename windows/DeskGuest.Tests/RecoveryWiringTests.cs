using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>
/// C20 WIRING regression suite: the owner-local recovery acts in
/// CoreRuntime (export / inspect / restore over the authenticated
/// companion channel), the agent-facing refusal module, the audit
/// discipline (fixed outcome strings — the key sheet and passphrases
/// never reach the log or the snapshot), and the empty-store /
/// live-identity gates at the host layer.
/// </summary>
public class RecoveryWiringTests
{
    private const string Passphrase = "correct horse battery staple";

    private static CoreRuntime Runtime(string dir) =>
        new(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });

    private static string AuditText(string dir) =>
        File.ReadAllText(Path.Combine(dir, "audit", "audit.jsonl"));

    private static (CoreRuntime Rt, string Dir, string BlobPath, string Sheet) Exported()
    {
        var dir = TestUtil.TempDir();
        var rt = Runtime(dir);
        var blobPath = Path.Combine(dir, "recovery.deskguestrecovery");
        var (ok, detail, exported, _, _) = rt.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "export",
            passphrase = Passphrase,
            outputPath = blobPath
        }));
        Assert.True(ok, detail);
        Assert.NotNull(exported);
        return (rt, dir, blobPath, exported!.KeySheet);
    }

    [Fact]
    public async Task AgentModule_RefusesExportAndRestore()
    {
        var module = new RecoveryBlobModule();
        var ctx = new ToolExecutionContext(
            TestUtil.BarePairing(Scopes.All, "p-admin"), TestUtil.Session(),
            TestUtil.State(), new HashSet<string>(), TestUtil.TempDir());
        foreach (var action in new[] { "export", "restore", "inspect" })
        {
            using var doc = JsonDocument.Parse($"{{\"action\":\"{action}\"}}");
            var result = await module.ExecuteAsync(doc.RootElement.Clone(), ctx, default);
            Assert.False(result.Ok);
            Assert.Equal("owner_only", result.ErrorClass);
        }
    }

    [Fact]
    public void OwnerExport_WritesBlob_AuditsWithoutSheetOrPassphrase()
    {
        var (rt, dir, blobPath, sheet) = Exported();
        Assert.True(File.Exists(blobPath));
        Assert.Equal(34, sheet.Split(' ').Length);

        var audit = AuditText(dir);
        Assert.Contains("recovery_exported", audit);
        Assert.DoesNotContain(sheet, audit);
        Assert.DoesNotContain(Passphrase, audit);
        // No single sheet word sequence either: the first 6 words as
        // a phrase must not appear anywhere in the log.
        Assert.DoesNotContain(string.Join(" ", sheet.Split(' ').Take(6)), audit);

        var snapshot = rt.BuildHostStateJson();
        Assert.Contains("recovery", snapshot);
        Assert.Contains(rt.Identity.DeviceId, snapshot);
        Assert.DoesNotContain(sheet, snapshot);
        Assert.DoesNotContain(Passphrase, snapshot);
    }

    [Fact]
    public void OwnerInspect_ReportsKindAndDevice()
    {
        var (rt, _, blobPath, _) = Exported();
        var (ok, detail, _, _, _) = rt.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "inspect",
            blobPath
        }));
        Assert.True(ok, detail);
        Assert.Contains("primary", detail);
        Assert.Contains(rt.Identity.DeviceId, detail);
    }

    [Fact]
    public async Task OwnerRestore_IntoFreshRuntime_ReplacesMintedIdentity_AndPersists()
    {
        var (source, _, blobPath, _) = Exported();
        var sourceId = source.Identity.DeviceId;

        var dirB = TestUtil.TempDir();
        var rtB = Runtime(dirB);
        Assert.NotEqual(sourceId, rtB.Identity.DeviceId); // fresh boot minted its own
        var (ok, detail, _, _, _) = rtB.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "restore_primary",
            blobPath,
            passphrase = Passphrase
        }));
        Assert.True(ok, detail);
        Assert.Equal(sourceId, rtB.Identity.DeviceId);
        Assert.Contains("recovery_restored", AuditText(dirB));
        Assert.Contains(sourceId, rtB.BuildHostStateJson());

        // Persistence: a new runtime over the same data dir loads
        // the restored identity from disk. W95 / FR-124 amendment:
        // the previous runtime must STOP first — the single-instance
        // guard refuses a second LIVE Core on the same data dir
        // (that refusal is exactly defect D-W93-1's fix); a stopped
        // predecessor is the true restart this pin always meant.
        await rtB.StopAsync(default);
        await rtB.DisposeAsync();
        var rtC = Runtime(dirB);
        Assert.Equal(sourceId, rtC.Identity.DeviceId);
        await rtC.StopAsync(default);
        await rtC.DisposeAsync();
    }

    [Fact]
    public async Task Restore_OverLoadedIdentity_RefusedLoudly()
    {
        var (source, _, blobPath, _) = Exported();
        var dirB = TestUtil.TempDir();
        var rtB = Runtime(dirB);
        var (ok1, detail1, _, _, _) = rtB.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "restore_primary",
            blobPath,
            passphrase = Passphrase
        }));
        Assert.True(ok1, detail1);

        // A runtime that LOADED its identity from disk holds a live
        // identity: restore refuses, and the refusal is audited with
        // the fixed string. W95 / FR-124 amendment: rtB stops before
        // rtC constructs (single-instance guard — see the sibling
        // pin); rtC still LOADS the restored identity from disk,
        // which is the state this pin exercises.
        await rtB.StopAsync(default);
        await rtB.DisposeAsync();
        var rtC = Runtime(dirB);
        var (ok, detail, _, _, _) = rtC.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "restore_primary",
            blobPath,
            passphrase = Passphrase
        }));
        Assert.False(ok);
        Assert.Contains("live identity", detail);
        Assert.Contains("recovery_restore_refused", AuditText(dirB));
        await rtC.StopAsync(default);
        await rtC.DisposeAsync();
        Assert.Equal(source.Identity.DeviceId, rtC.Identity.DeviceId); // untouched
    }

    [Fact]
    public void Restore_WrongPassphrase_Refused_NothingTouched_SecretNotLogged()
    {
        var (_, _, blobPath, _) = Exported();
        var dirD = TestUtil.TempDir();
        var rtD = Runtime(dirD);
        var mintedId = rtD.Identity.DeviceId;
        const string wrong = "wrong passphrase entirely";
        var (ok, detail, _, _, _) = rtD.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "restore_primary",
            blobPath,
            passphrase = wrong
        }));
        Assert.False(ok);
        Assert.Contains("passphrase", detail); // loud refusal
        Assert.Equal(mintedId, rtD.Identity.DeviceId);
        var audit = AuditText(dirD);
        Assert.Contains("recovery_restore_refused", audit);
        Assert.DoesNotContain(wrong, audit);
    }

    [Fact]
    public void Restore_WithKeySheet_Works_AndSheetNeverLogged()
    {
        var (source, _, blobPath, sheet) = Exported();
        var dirE = TestUtil.TempDir();
        var rtE = Runtime(dirE);
        var (ok, detail, _, _, _) = rtE.ApplyRecoveryAction(JsonSerializer.Serialize(new
        {
            action = "restore_primary",
            blobPath,
            keySheet = sheet
        }));
        Assert.True(ok, detail);
        Assert.Equal(source.Identity.DeviceId, rtE.Identity.DeviceId);
        var audit = AuditText(dirE);
        Assert.Contains("recovery_restored", audit);
        Assert.DoesNotContain(sheet, audit);
        Assert.DoesNotContain(string.Join(" ", sheet.Split(' ').Take(6)), audit);
    }
}
