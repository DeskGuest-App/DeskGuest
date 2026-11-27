using System.Security.Cryptography;
using System.Text;
using DeskGuest.Core;
using DeskGuest.Shared.AiPack;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tor;

namespace DeskGuest.Tests;

/// <summary>Wave 19 Lane C — Windows wiring gaps (the W18 deploy
/// findings): Tor provisioning and the AiPack download were built
/// but unreachable in the shipped v18 surface. These tests drive
/// the NEW production surfaces — IpcKinds.TorAction through
/// CoreRuntime.ApplyTorActionAsync and the aipack download /
/// download_status / download_cancel actions through
/// CoreRuntime.ApplyAiPackAction — plus the policy toggles both
/// acts consult, and the destruction cases for the new download
/// path (forged manifest, mid-download tamper, cancel, resume).
/// No test here touches the network: the Tor setup act itself is
/// exercised only up to its policy gate (its provisioning legs are
/// fixture-proven in TorProvisioningTests), and every AiPack
/// download runs against fixture manifests + fixture fetchers.</summary>
public class W19WinWireTests
{
    private static CoreRuntime NewRuntime(string dir) => new(new CoreOptions
    {
        DataDir = dir, Port = 18919, Protector = new DevOnlyPassThroughProtector(),
        Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
    });

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // ---- policy toggles (TOTAL POLICY CONTROL) ----------------------

    [Fact]
    public void Registry_TorAndAiPackToggles_Registered_DefaultOn()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet(CoreRuntime.TorProvisioningPolicyKey, out var tor));
        Assert.True(tor!.DefaultEnabled);
        Assert.True(registry.TryGet(CoreRuntime.AiPackDownloadPolicyKey, out var pack));
        Assert.True(pack!.DefaultEnabled);
        // The engine resolves both keys (an unregistered key would
        // fail closed and the acts could never run).
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev-wire", "");
        Assert.True(engine.IsEnabled(facts, CoreRuntime.TorProvisioningPolicyKey));
        Assert.True(engine.IsEnabled(facts, CoreRuntime.AiPackDownloadPolicyKey));
    }

    // ---- Tor surface -------------------------------------------------

    [Fact]
    public async Task TorAction_Status_OnFreshRuntime_HonestlyUnconfigured()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var (ok, detail) = await runtime.ApplyTorActionAsync("{\"action\":\"status\"}");
        Assert.True(ok, detail);
        Assert.Contains("tor state: unconfigured", detail);
        Assert.Contains("no tor.json", detail);
        // The onion-service gap is named as a design item, never
        // faked into existence.
        Assert.Contains("DESIGN ITEM", detail);
        Assert.Contains("client-only", detail);
    }

    [Fact]
    public async Task TorAction_Unknown_AndMalformed_Refused()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        Assert.False((await runtime.ApplyTorActionAsync("{\"action\":\"explode\"}")).Ok);
        Assert.False((await runtime.ApplyTorActionAsync("{not json")).Ok);
        Assert.False((await runtime.ApplyTorActionAsync(null)).Ok);
    }

    [Fact]
    public async Task TorAction_Stop_OnFreshRuntime_Unconfigures()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var (ok, detail) = await runtime.ApplyTorActionAsync("{\"action\":\"stop\"}");
        Assert.True(ok, detail);
        Assert.Contains("unconfigured", detail);
        Assert.False(File.Exists(runtime.TorSetup.TorConfigPath));
    }

    [Fact]
    public async Task TorAction_Setup_PolicyDisabled_RefusesBeforeAnyProvisioning()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var admitted = runtime.ManagementPolicies.AdmitLocalDocument(
            new ManagementPolicyDocument("wire-tor-off", PolicyLevels.Device, runtime.Identity.DeviceId,
                new Dictionary<string, string> { [CoreRuntime.TorProvisioningPolicyKey] = "false" }, 1),
            "W19-C test");
        Assert.True(admitted.Allowed, admitted.Reason);
        var (ok, detail) = await runtime.ApplyTorActionAsync("{\"action\":\"setup\"}");
        Assert.False(ok);
        Assert.Contains("disabled by management policy", detail);
        // The gate fired BEFORE the act: nothing provisioned, no
        // tor.json, status still honestly unconfigured.
        Assert.False(File.Exists(runtime.TorSetup.TorConfigPath));
        Assert.False(Directory.Exists(runtime.TorSetup.ComponentHome) &&
                     Directory.EnumerateFiles(runtime.TorSetup.ComponentHome, "*", SearchOption.AllDirectories).Any());
        var status = await runtime.ApplyTorActionAsync("{\"action\":\"status\"}");
        Assert.Contains("tor state: unconfigured", status.Detail);
    }

    // ---- AiPack surface ----------------------------------------------

    [Fact]
    public void AiPackAction_PackHome_IsUnderDataDir_NeverHardcodedDrive()
    {
        var dir = TestUtil.TempDir();
        var runtime = NewRuntime(dir);
        Assert.Equal(Path.Combine(dir, "aipack", AiPackManifest.UiTars15_7B.PackId), runtime.AiPackHome);
        var (ok, detail) = runtime.ApplyAiPackAction("{\"action\":\"status\"}");
        Assert.True(ok, detail);
        Assert.Contains(runtime.AiPackHome, detail);
        Assert.Contains("not_started", detail);
    }

    [Fact]
    public void AiPackAction_Download_WithoutLicence_Refused_NothingStarts()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var (ok, detail) = runtime.ApplyAiPackAction("{\"action\":\"download\"}");
        Assert.False(ok);
        Assert.Contains("licence not accepted", detail);
        Assert.Equal("not_started", runtime.AiPackDownloadSnapshot().State);
    }

    [Fact]
    public void AiPackAction_Download_ForeignDirectory_RefusedByName()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        Assert.True(runtime.ApplyAiPackAction("{\"action\":\"accept_licence\",\"userId\":\"operator\"}").Ok);
        var (ok, detail) = runtime.ApplyAiPackAction("{\"action\":\"download\",\"directory\":\"D:\\\\DeskGuest-AiPack\\\\ui-tars-1.5-7b\"}");
        Assert.False(ok);
        Assert.Contains("pack home", detail);
        Assert.Equal("not_started", runtime.AiPackDownloadSnapshot().State);
    }

    [Fact]
    public void AiPackAction_Download_PolicyDisabled_Refuses()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        Assert.True(runtime.ApplyAiPackAction("{\"action\":\"accept_licence\",\"userId\":\"operator\"}").Ok);
        var admitted = runtime.ManagementPolicies.AdmitLocalDocument(
            new ManagementPolicyDocument("wire-pack-off", PolicyLevels.Device, runtime.Identity.DeviceId,
                new Dictionary<string, string> { [CoreRuntime.AiPackDownloadPolicyKey] = "false" }, 1),
            "W19-C test");
        Assert.True(admitted.Allowed, admitted.Reason);
        var (ok, detail) = runtime.ApplyAiPackAction("{\"action\":\"download\"}");
        Assert.False(ok);
        Assert.Contains("disabled by management policy", detail);
        Assert.Equal("not_started", runtime.AiPackDownloadSnapshot().State);
    }

    [Fact]
    public void AiPackAction_DownloadCancel_AndStatus_WhenIdle()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var cancel = runtime.ApplyAiPackAction("{\"action\":\"download_cancel\"}");
        Assert.False(cancel.Ok);
        Assert.Contains("no download is in progress", cancel.Detail);
        var status = runtime.ApplyAiPackAction("{\"action\":\"download_status\"}");
        Assert.True(status.Ok, status.Detail);
        Assert.Contains("not_started", status.Detail);
        Assert.Contains("resumable", status.Detail);
    }

    // ---- AiPack download destruction (fixture-proven) -----------------

    private static (AiPackService Svc, PackFile[] Files, byte[][] Bytes) FixturePack(int count = 2)
    {
        var bytes = Enumerable.Range(0, count)
            .Select(i => Encoding.UTF8.GetBytes($"fixture-weights-{i}-" + new string('x', 64))).ToArray();
        var files = bytes.Select((b, i) => new PackFile($"model-{i}.bin", Sha256Hex(b), b.Length)).ToArray();
        var svc = new AiPackService(AiPackManifest.ForFixture("fixture://local", files));
        svc.AcceptLicence("operator");
        return (svc, files, bytes);
    }

    [Fact]
    public async Task AiPackDownload_ForgedManifest_RefusesBeforeAnyFetch()
    {
        var (_, files, _) = FixturePack();
        // A pin edited to match a tampered artefact: the manifest
        // digest no longer matches the pin list, so the download
        // refuses BEFORE any fetch (the AiPack discipline).
        var forged = AiPackManifest.ForFixture("fixture://local", files) with
        {
            ManifestDigest = new string('0', 64),
        };
        var svc = new AiPackService(forged);
        svc.AcceptLicence("operator");
        var fetches = 0;
        Task Fetch(string url, string dest, CancellationToken ct) { fetches++; return Task.CompletedTask; }
        var (ok, detail) = await svc.DownloadAsync(TestUtil.TempDir(), Fetch, fixtureMode: true);
        Assert.False(ok);
        Assert.Contains("manifest integrity failure", detail);
        Assert.Equal(0, fetches);
    }

    [Fact]
    public async Task AiPackDownload_MidDownloadTamper_Refuses_ThenResumeSkipsVerified()
    {
        var (svc, files, bytes) = FixturePack();
        var dir = TestUtil.TempDir();
        var fetchCounts = new Dictionary<string, int>();
        var tamperSecond = true;
        Task Fetch(string url, string dest, CancellationToken ct)
        {
            var name = url.Split('/')[^1];
            fetchCounts[name] = fetchCounts.GetValueOrDefault(name) + 1;
            var idx = int.Parse(name[6].ToString());
            var payload = tamperSecond && idx == 1
                ? Encoding.UTF8.GetBytes("tampered-mid-download-bytes-that-match-nothing")
                : bytes[idx];
            // Tampered payload must also fail the SIZE check path or
            // the hash path — either refuses; use same-length tamper
            // so the HASH check is the one that fires.
            if (tamperSecond && idx == 1)
                payload = bytes[idx].Select(b => (byte)(b ^ 0xFF)).ToArray();
            return File.WriteAllBytesAsync(dest, payload, ct);
        }
        var first = await svc.DownloadAsync(dir, Fetch, fixtureMode: true);
        Assert.False(first.Ok);
        Assert.Contains("HASH MISMATCH", first.Detail);
        // File 0 landed verified; file 1 never landed, partial gone.
        Assert.True(File.Exists(Path.Combine(dir, files[0].RelativePath)));
        Assert.False(File.Exists(Path.Combine(dir, files[1].RelativePath)));
        Assert.False(File.Exists(Path.Combine(dir, files[1].RelativePath + ".partial")));
        // Resume with an honest source: file 0 is NOT re-fetched
        // (it still verifies), file 1 is fetched and lands.
        tamperSecond = false;
        var second = await svc.DownloadAsync(dir, Fetch, fixtureMode: true);
        Assert.True(second.Ok, second.Detail);
        Assert.Equal(1, fetchCounts[files[0].RelativePath]);
        Assert.Equal(2, fetchCounts[files[1].RelativePath]);
        Assert.True((await svc.VerifyInstalledAsync(dir)).Ok);
    }

    [Fact]
    public async Task AiPackDownload_LandedFileTamperedAfterInstall_IsRefetchedNotTrusted()
    {
        var (svc, files, bytes) = FixturePack(1);
        var dir = TestUtil.TempDir();
        var fetches = 0;
        Task Fetch(string url, string dest, CancellationToken ct)
        {
            fetches++;
            return File.WriteAllBytesAsync(dest, bytes[0], ct);
        }
        Assert.True((await svc.DownloadAsync(dir, Fetch, fixtureMode: true)).Ok);
        // Tamper with the landed file (same length): the resume
        // path must NOT skip-verify it — it is deleted + re-fetched.
        var landed = Path.Combine(dir, files[0].RelativePath);
        var onDisk = await File.ReadAllBytesAsync(landed);
        await File.WriteAllBytesAsync(landed, onDisk.Select(b => (byte)(b ^ 0xFF)).ToArray());
        Assert.True((await svc.DownloadAsync(dir, Fetch, fixtureMode: true)).Ok);
        Assert.Equal(2, fetches);
        Assert.True((await svc.VerifyInstalledAsync(dir)).Ok);
    }

    [Fact]
    public async Task AiPackDownload_Cancel_MidFile_NothingLands_PartialGone()
    {
        var (svc, files, _) = FixturePack(1);
        var dir = TestUtil.TempDir();
        using var cts = new CancellationTokenSource();
        var fetchEntered = new TaskCompletionSource();
        async Task Fetch(string url, string dest, CancellationToken ct)
        {
            fetchEntered.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct); // in-flight until cancelled
        }
        var run = svc.DownloadAsync(dir, Fetch, fixtureMode: true, ct: cts.Token);
        await fetchEntered.Task;
        cts.Cancel();
        var (ok, _) = await run;
        Assert.False(ok);
        Assert.False(File.Exists(Path.Combine(dir, files[0].RelativePath)));
        Assert.False(File.Exists(Path.Combine(dir, files[0].RelativePath + ".partial")));
    }

    // ---- Tor provisioning destruction (through the new surface's legs) --

    [Fact]
    public async Task TorProvision_ForgedManifest_RefusesBeforeAnyFetch()
    {
        var artefact = TorComponentManifest.Production.ForPlatform(TorPins.WindowsX64)!;
        var forged = new TorComponentManifest(
            TorComponentManifest.Production.BundleVersion, TorComponentManifest.Production.TorVersion,
            TorComponentManifest.Production.DownloadBaseUrl, new[] { artefact }, "unaudited",
            ManifestDigest: new string('0', 64));
        var prov = new TorProvisioner(forged);
        var fetches = 0;
        Task Fetch(string url, string dest, CancellationToken ct) { fetches++; return Task.CompletedTask; }
        var (ok, detail) = await prov.ProvisionAsync(TestUtil.TempDir(), artefact, Fetch);
        Assert.False(ok);
        Assert.Contains("manifest integrity failure", detail);
        Assert.Equal(0, fetches);
    }
}
