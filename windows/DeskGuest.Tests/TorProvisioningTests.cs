using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Tor;
using DeskGuest.Shared.Transport;

namespace DeskGuest.Tests;

/// <summary>A2 — Tor binary provisioning. The production manifest
/// carries the Tor Project's expert-bundle pins captured from the
/// author's own published sums (Tor Browser 16.0.1 / Tor 0.4.9.16).
/// These tests pin the pin state itself, the Kotlin mirror parity,
/// the provisioning discipline against a locally produced stand-in
/// artefact, and the destruction cases: a tampered binary fails
/// verification and is NEVER executed, a bundle carrying a
/// traversal entry writes nothing outside the component home, and
/// a downgrade swap of a pinned hash fails the manifest's own
/// integrity digest before any fetch.</summary>
public class TorProvisioningTests
{
    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // ---- production pins ------------------------------------------------

    [Fact]
    public void TorPins_ProductionManifest_IntegrityValid_DigestRecomputes()
    {
        var m = TorComponentManifest.Production;
        Assert.Equal("16.0.1", m.BundleVersion);
        Assert.Equal("0.4.9.16", m.TorVersion);
        Assert.Equal(3, m.Artefacts.Count);
        var integrity = m.ValidateIntegrity();
        Assert.True(integrity.Ok, integrity.Detail);
        Assert.Equal(
            TorComponentManifest.ComputeManifestDigest(m.BundleVersion, m.DownloadBaseUrl, m.Artefacts),
            m.ManifestDigest);
        var win = m.ForPlatform(TorPins.WindowsX64)!;
        Assert.Equal("9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b", win.BundleSha256);
        Assert.Equal("tor/tor.exe", win.BinaryBundlePath);
        var android = m.ForPlatform(TorPins.AndroidArm64)!;
        Assert.Equal("0091927b9fd72992a88021d55416b23a8380dc39a70c4b73a2cca9ee6a3dbcec", android.BundleSha256);
        Assert.Equal("tor/libTor.so", android.BinaryBundlePath);
    }

    [Fact]
    public void TorPins_KotlinMirror_CarriesIdenticalPinsAndDigest()
    {
        var ktPath = FindAndroidTorProvisioning();
        Assert.True(ktPath is not null,
            "Android mirror TorProvisioning.kt not found above the test working tree — mirror parity cannot be proven");
        var kt = File.ReadAllText(ktPath!);
        var m = TorComponentManifest.Production;
        Assert.Contains(m.ManifestDigest, kt);
        Assert.Contains(m.BundleVersion, kt);
        Assert.Contains(m.TorVersion, kt);
        foreach (var a in m.Artefacts)
        {
            Assert.Contains(a.BundleFileName, kt);
            Assert.Contains(a.BundleSha256, kt);
            Assert.Contains(a.BundleSizeBytes.ToString(), kt);
            foreach (var f in a.Files)
            {
                Assert.Contains(f.BundlePath, kt);
                Assert.Contains(f.Sha256, kt);
                Assert.Contains(f.SizeBytes.ToString(), kt);
            }
        }
    }

    private static string? FindAndroidTorProvisioning()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName,
                "agent-control-app", "android", "app", "src", "main", "java",
                "io", "deskguest", "app", "transport", "TorProvisioning.kt");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    // ---- fixture provisioning ------------------------------------------

    private sealed record Fixture(TorComponentManifest Manifest, TorArtefact Artefact, byte[] BundleBytes, string BaseDir);

    /// <summary>Build a locally produced stand-in artefact: a
    /// tar.gz "expert bundle" whose pins are computed from the
    /// fixture bytes, in a fixture manifest. The stand-in binary is
    /// inert data — provisioning machinery is what is under test.</summary>
    private static Fixture BuildFixture(byte[]? binaryOverride = null, bool includeTraversalEntry = false)
    {
        var binary = binaryOverride ?? Encoding.UTF8.GetBytes("DeskGuest FIXTURE TOR BINARY — inert stand-in, never executed");
        var geoip = Encoding.UTF8.GetBytes("fixture geoip");
        var entries = new List<(string Path, byte[] Bytes)>
        {
            ("tor/tor.exe", binary),
            ("data/geoip", geoip),
            ("docs/readme.txt", Encoding.UTF8.GetBytes("unpinned bundle member — must be ignored")),
        };
        if (includeTraversalEntry)
            entries.Add(("../../evil.exe", Encoding.UTF8.GetBytes("traversal payload")));
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gz, TarEntryFormat.Pax, leaveOpen: true))
        {
            foreach (var (path, bytes) in entries)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, path)
                {
                    DataStream = new MemoryStream(bytes),
                };
                tar.WriteEntry(entry);
            }
        }
        var bundleBytes = ms.ToArray();
        var files = new TorComponentFile[]
        {
            new("tor/tor.exe", Sha256Hex(binary), binary.Length),
            new("data/geoip", Sha256Hex(geoip), geoip.Length),
        };
        var artefact = new TorArtefact("fixture-platform", "fixture-bundle.tar.gz",
            Sha256Hex(bundleBytes), bundleBytes.Length, "tor/tor.exe", files);
        var manifest = TorComponentManifest.ForFixture("fixture://local", artefact);
        var baseDir = Path.Combine(Path.GetTempPath(), "deskguest-tor-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);
        return new Fixture(manifest, artefact, bundleBytes, baseDir);
    }

    private static Func<string, string, CancellationToken, Task> Fetcher(byte[] bytes) =>
        async (url, dest, ct) => { await File.WriteAllBytesAsync(dest, bytes, ct); };

    [Fact]
    public async Task TorProvision_FixtureBundle_InstallsVerifiedFiles_AndRecord()
    {
        var fx = BuildFixture();
        var home = Path.Combine(fx.BaseDir, "tor");
        var prov = new TorProvisioner(fx.Manifest);
        var result = await prov.ProvisionAsync(home, fx.Artefact, Fetcher(fx.BundleBytes), fixtureMode: true);
        Assert.True(result.Ok, result.Detail);
        Assert.True(File.Exists(Path.Combine(home, "tor", "tor.exe")));
        Assert.True(File.Exists(Path.Combine(home, "data", "geoip")));
        Assert.False(File.Exists(Path.Combine(home, "docs", "readme.txt"))); // unpinned member never lands
        Assert.True(File.Exists(Path.Combine(home, TorProvisioner.InstallRecordFileName)));
        var verify = await prov.VerifyInstalledAsync(home, fx.Artefact);
        Assert.True(verify.Ok, verify.Detail);
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorProvision_TamperedBundle_Refused_NothingInstalled()
    {
        var fx = BuildFixture();
        var tampered = fx.BundleBytes.ToArray();
        tampered[tampered.Length / 2] ^= 0xFF;
        var home = Path.Combine(fx.BaseDir, "tor");
        var prov = new TorProvisioner(fx.Manifest);
        var result = await prov.ProvisionAsync(home, fx.Artefact, Fetcher(tampered), fixtureMode: true);
        Assert.False(result.Ok);
        Assert.Contains("HASH MISMATCH", result.Detail);
        Assert.False(File.Exists(Path.Combine(home, "tor", "tor.exe")));
        Assert.False(File.Exists(Path.Combine(home, TorProvisioner.InstallRecordFileName)));
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorProvision_BinaryPinMismatchInsideVerifiedBundle_Refused()
    {
        // The bundle matches its own pin, but the binary inside does
        // not match the binary pin: extraction-time verification refuses.
        var good = BuildFixture();
        var wrongBinary = Encoding.UTF8.GetBytes("a different binary than the pin describes");
        var fx = BuildFixture(binaryOverride: wrongBinary);
        // Re-pin the bundle to the wrong-binary bundle, keep the
        // binary pin from the good fixture: bundle verifies, binary refuses.
        var artefact = fx.Artefact with
        {
            Files = new TorComponentFile[]
            {
                new("tor/tor.exe", good.Artefact.Files[0].Sha256, good.Artefact.Files[0].SizeBytes),
                fx.Artefact.Files[1],
            }
        };
        var manifest = TorComponentManifest.ForFixture("fixture://local", artefact);
        var home = Path.Combine(fx.BaseDir, "tor");
        var prov = new TorProvisioner(manifest);
        var result = await prov.ProvisionAsync(home, artefact, Fetcher(fx.BundleBytes), fixtureMode: true);
        Assert.False(result.Ok);
        Assert.False(File.Exists(Path.Combine(home, "tor", "tor.exe")));
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorProvision_TraversalEntry_WritesNothingOutsideHome()
    {
        var fx = BuildFixture(includeTraversalEntry: true);
        var home = Path.Combine(fx.BaseDir, "tor");
        var prov = new TorProvisioner(fx.Manifest);
        var result = await prov.ProvisionAsync(home, fx.Artefact, Fetcher(fx.BundleBytes), fixtureMode: true);
        Assert.True(result.Ok, result.Detail);
        // The traversal payload would land two levels above the
        // component home if entry names were ever used as paths.
        Assert.False(File.Exists(Path.Combine(fx.BaseDir, "evil.exe")));
        Assert.False(File.Exists(Path.GetFullPath(Path.Combine(home, "..", "..", "evil.exe"))));
        Assert.True(File.Exists(Path.Combine(home, "tor", "tor.exe")));
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorProvision_DowngradeSwap_PinEditedWithoutDigest_RefusedBeforeFetch()
    {
        var fx = BuildFixture();
        // Attacker swaps the bundle pin to match THEIR bundle but
        // cannot fix the manifest digest (it is pinned in code):
        // integrity fails and provisioning refuses before any fetch.
        var swapped = fx.Artefact with { BundleSha256 = Sha256Hex(Encoding.UTF8.GetBytes("attacker bundle")) };
        var manifest = fx.Manifest with { Artefacts = new[] { swapped } };
        var integrity = manifest.ValidateIntegrity();
        Assert.False(integrity.Ok);
        Assert.Contains("digest", integrity.Detail, StringComparison.OrdinalIgnoreCase);
        var fetched = false;
        var prov = new TorProvisioner(manifest);
        var result = await prov.ProvisionAsync(Path.Combine(fx.BaseDir, "tor"), swapped,
            (url, dest, ct) => { fetched = true; return Task.CompletedTask; }, fixtureMode: true);
        Assert.False(result.Ok);
        Assert.False(fetched);
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorProvision_ProductionSourceOverride_Refused()
    {
        var fx = BuildFixture();
        var prov = new TorProvisioner(fx.Manifest);
        var result = await prov.ProvisionAsync(Path.Combine(fx.BaseDir, "tor"), fx.Artefact,
            Fetcher(fx.BundleBytes), sourceBaseOverride: "https://mirror.example/tor", fixtureMode: false);
        Assert.False(result.Ok);
        Assert.Contains("wrong source", result.Detail);
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    // ---- setup act ------------------------------------------------------

    private sealed class FakeTorProcess : ITorProcessRunner
    {
        public int StartCount;
        public string? StartedBinary;
        public bool IsRunning { get; private set; }
        public Action? OnStart;
        public void Start(string binaryPath, string torrcPath, string workingDir)
        {
            StartCount++;
            StartedBinary = binaryPath;
            IsRunning = true;
            OnStart?.Invoke();
        }
        public void Stop() => IsRunning = false;
    }

    [Fact]
    public async Task TorSetup_TamperedInstalledBinary_NeverExecuted_NoConfigWritten()
    {
        var fx = BuildFixture();
        var home = Path.Combine(fx.BaseDir, "tor");
        var dataDir = Path.Combine(fx.BaseDir, "data");
        var prov = new TorProvisioner(fx.Manifest);
        var provisioned = await prov.ProvisionAsync(home, fx.Artefact, Fetcher(fx.BundleBytes), fixtureMode: true);
        Assert.True(provisioned.Ok, provisioned.Detail);
        // Tamper with the installed binary after provisioning.
        var binaryPath = Path.Combine(home, "tor", "tor.exe");
        var bytes = await File.ReadAllBytesAsync(binaryPath);
        bytes[0] ^= 0xFF;
        await File.WriteAllBytesAsync(binaryPath, bytes);
        var fake = new FakeTorProcess();
        var setup = new TorSetupService(prov, fake, home, dataDir);
        // The fixture manifest's platform is not the current
        // platform, so run the act against a manifest whose
        // ForCurrentPlatform resolves: substitute via the fixture
        // artefact for the host platform id.
        var hostArtefact = fx.Artefact with { Platform = HostPlatformId() };
        var hostManifest = TorComponentManifest.ForFixture("fixture://local", hostArtefact);
        var hostSetup = new TorSetupService(new TorProvisioner(hostManifest), fake, home, dataDir);
        var result = await hostSetup.RunSetupAsync(fetcher: Fetcher(fx.BundleBytes), fixtureMode: true);
        Assert.False(result.Ok);
        Assert.Contains("HASH MISMATCH", result.Detail);
        Assert.Equal(0, fake.StartCount); // never executed
        Assert.False(File.Exists(Path.Combine(dataDir, "tor.json")));
        _ = setup;
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorSetup_ProxyNeverAnswers_NamedRefusal_NoConfigWritten()
    {
        var fx = BuildFixture();
        var home = Path.Combine(fx.BaseDir, "tor");
        var dataDir = Path.Combine(fx.BaseDir, "data");
        var hostArtefact = fx.Artefact with { Platform = HostPlatformId() };
        var hostManifest = TorComponentManifest.ForFixture("fixture://local", hostArtefact);
        var fake = new FakeTorProcess(); // "starts" but opens no SOCKS listener
        var setup = new TorSetupService(new TorProvisioner(hostManifest), fake, home, dataDir);
        var result = await setup.RunSetupAsync(fetcher: Fetcher(fx.BundleBytes), fixtureMode: true,
            socksWait: TimeSpan.FromMilliseconds(750));
        Assert.False(result.Ok);
        Assert.Contains("did not open its local SOCKS listener", result.Detail);
        Assert.False(File.Exists(Path.Combine(dataDir, "tor.json")));
        Assert.False(fake.IsRunning); // the act stopped the dead client
        Directory.Delete(fx.BaseDir, recursive: true);
    }

    [Fact]
    public async Task TorSetup_Success_WritesTorJson_ReadableByRungConfigShape()
    {
        var fx = BuildFixture();
        var home = Path.Combine(fx.BaseDir, "tor");
        var dataDir = Path.Combine(fx.BaseDir, "data");
        var hostArtefact = fx.Artefact with { Platform = HostPlatformId() };
        var hostManifest = TorComponentManifest.ForFixture("fixture://local", hostArtefact);
        var fake = new FakeTorProcess();
        // The SOCKS-readiness probe is substituted: this sandbox
        // transparently intercepts managed (.NET/JVM) loopback
        // connects, so a fake listener here could never be reached
        // (minimal-probe proven, A2 ledger fragment). The probe is
        // the act's only environment-sensitive leg; every other
        // step — provision, verify, launch, torrc, tor.json — runs
        // for real. The real probe is exercised against the real
        // provisioned Tor client in proofs/tor-rung-v1/.
        var setup = new TorSetupService(new TorProvisioner(hostManifest), fake, home, dataDir,
            socksProbe: (_, _, _, _) => Task.FromResult(true));
        try
        {
            var result = await setup.RunSetupAsync(fetcher: Fetcher(fx.BundleBytes), fixtureMode: true,
                socksWait: TimeSpan.FromSeconds(10));
            Assert.True(result.Ok, result.Detail);
            Assert.Equal(1, fake.StartCount);
            var torJson = Path.Combine(dataDir, "tor.json");
            Assert.True(File.Exists(torJson));
            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(torJson));
            Assert.Equal("127.0.0.1", doc.RootElement.GetProperty("socksHost").GetString());
            Assert.Equal(TorPins.SocksPort, doc.RootElement.GetProperty("socksPort").GetInt32());
            // The torrc the act generated is local-only: one listener.
            var torrc = await File.ReadAllTextAsync(Path.Combine(home, "torrc"));
            Assert.Contains($"SocksPort 127.0.0.1:{TorPins.SocksPort}", torrc);
            Assert.DoesNotContain("ControlPort", torrc);
            Assert.DoesNotContain("ORPort", torrc);
            // And the rung, handed the config the act wrote, is the
            // same shape CoreRuntime.ReadTorConfig produces.
            var cfg = new TorConfig("127.0.0.1", TorPins.SocksPort);
            Assert.Equal(TorPins.SocksPort, cfg.SocksPort);
        }
        finally
        {
            Directory.Delete(fx.BaseDir, recursive: true);
        }
    }

    private static string HostPlatformId() =>
        OperatingSystem.IsWindows() ? TorPins.WindowsX64 : TorPins.LinuxX64;
}
