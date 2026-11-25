using Acp.Core;
using Acp.Core.Phase2;

namespace Acp.Tests;

/// <summary>The vault-seeding path (install-night gap, 2026-11-14):
/// the shipped build had UnlockService.VaultPasswordFromLaptop with
/// NOTHING able to call it — no IPC kind, no laptop UI. These tests
/// pin the Core side of the fix: a payload arriving over the
/// (authenticated-channel-only) ApplyVaultFromLaptopAsync vaults the
/// credential, settles the module state, and NEVER writes the
/// password to the audit log; malformed payloads are refused
/// quietly; the wipe path empties the vault again.</summary>
public sealed class VaultIpcTests : IAsyncLifetime
{
    private readonly string _dataDir = TestUtil.TempDir();
    private CoreRuntime _runtime = null!;

    public Task InitializeAsync()
    {
        _runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = _dataDir,
            FactChecks = new FakeFactChecks(),
        });
        // NOTE: ModuleEnabled is deliberately NOT set here — CoreRuntime
        // wires it (install-night defect #5). These tests fail if the
        // production construction ever leaves the module disabled again.
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _runtime.DisposeAsync();

    [Fact]
    public async Task VaultFromLaptop_SeedsCredential_StateReady_PasswordNeverAudited()
    {
        const string password = "correct-horse-battery-staple-TEST-ONLY";
        var ok = await _runtime.ApplyVaultFromLaptopAsync($"{{\"password\":\"{password}\"}}");
        Assert.True(ok);
        Assert.Equal(UnlockModuleState.Ready, _runtime.Unlock.State);

        var auditText = await File.ReadAllTextAsync(Path.Combine(_dataDir, "audit", "audit.jsonl"));
        Assert.Contains("vault_seeded_via_agent", auditText);
        Assert.DoesNotContain(password, auditText);
    }

    [Fact]
    public async Task VaultFromLaptop_MalformedPayloads_RefusedQuietly()
    {
        Assert.False(await _runtime.ApplyVaultFromLaptopAsync(null));
        Assert.False(await _runtime.ApplyVaultFromLaptopAsync("not json"));
        Assert.False(await _runtime.ApplyVaultFromLaptopAsync("{}"));
        Assert.False(await _runtime.ApplyVaultFromLaptopAsync("{\"password\":\"\"}"));
        await _runtime.Unlock.RefreshStateAsync(default);
        Assert.Equal(UnlockModuleState.VaultEmpty, _runtime.Unlock.State);
    }

    [Fact]
    public async Task VaultWipeFromLaptop_EmptiesVault()
    {
        Assert.True(await _runtime.ApplyVaultFromLaptopAsync("{\"password\":\"wipe-me-TEST-ONLY\"}"));
        Assert.Equal(UnlockModuleState.Ready, _runtime.Unlock.State);

        Assert.True(await _runtime.ApplyVaultWipeFromLaptopAsync());
        Assert.Equal(UnlockModuleState.VaultEmpty, _runtime.Unlock.State);

        var auditText = await File.ReadAllTextAsync(Path.Combine(_dataDir, "audit", "audit.jsonl"));
        Assert.Contains("vault_wiped_via_agent", auditText);
        Assert.DoesNotContain("wipe-me-TEST-ONLY", auditText);
    }
}
