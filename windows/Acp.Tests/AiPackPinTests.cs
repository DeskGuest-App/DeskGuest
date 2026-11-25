using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Acp.Shared.AiPack;

namespace Acp.Tests;

/// <summary>A3 — production AI-pack pins. The production manifest
/// (UI-TARS-1.5-7B) now carries pins captured from the author's own
/// Hugging Face listing (see Acp.Shared/AiPack/AiPack.cs header and
/// proofs/aipack-pin-capture/capture-record.json). These tests pin
/// the pin state itself: captured flag consistency, manifest
/// integrity digest, C#/Kotlin mirror parity, and the destruction
/// cases — a tampered artefact fails the pinned hash, and a
/// manifest edited to match a tampered artefact fails the
/// manifest's own integrity protection before any fetch.</summary>
public class AiPackPinTests
{
    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    [Fact]
    public void AiPackPins_ProductionManifest_Captured_Consistent_IntegrityValid()
    {
        var m = AiPackManifest.UiTars15_7B;
        Assert.True(m.PinsCaptured);
        Assert.Equal(m.Files.Count > 0, m.PinsCaptured); // PinsCaptured == (Files.Count > 0)
        Assert.Equal(19, m.Files.Count); // the author's listing at the captured commit, in listing order
        Assert.All(m.Files, f =>
        {
            Assert.Equal(64, f.Sha256.Length);
            Assert.True(f.SizeBytes > 0);
        });
        Assert.Equal(m.Files.Count, m.Files.Select(f => f.RelativePath).Distinct().Count());
        var integrity = m.ValidateIntegrity();
        Assert.True(integrity.Ok, integrity.Detail);
        Assert.Equal(
            AiPackManifest.ComputeManifestDigest(m.PackId, m.OfficialBaseUrl, m.Files),
            m.ManifestDigest);
    }

    [Fact]
    public void AiPackPins_KotlinMirror_CarriesIdenticalFilesAndDigest()
    {
        var ktPath = FindAndroidAiPack();
        Assert.True(ktPath is not null,
            "Android mirror AiPack.kt not found above the test working tree — mirror parity cannot be proven");
        var kt = File.ReadAllText(ktPath!);
        var entries = Regex.Matches(kt,
                "PackFile\\(\"([^\"]+)\",\\s*\"([0-9a-f]{64})\",\\s*(\\d+)L\\)")
            .Select(mm => new PackFile(mm.Groups[1].Value, mm.Groups[2].Value, long.Parse(mm.Groups[3].Value)))
            .ToList();
        var prod = AiPackManifest.UiTars15_7B;
        Assert.Equal(prod.Files.Count, entries.Count);
        Assert.Equal(prod.Files, entries); // identical file lists and pins, same order
        var digest = Regex.Match(kt, "manifestDigest = \"([0-9a-f]{64})\"");
        Assert.True(digest.Success, "Kotlin mirror carries no manifest digest");
        Assert.Equal(prod.ManifestDigest, digest.Groups[1].Value);
        Assert.Contains("pinsCaptured = true", kt);
    }

    private static string? FindAndroidAiPack()
    {
        const string rel = "agent-control-app/android/app/src/main/java/io/agenticcontrol/app/aipack/AiPack.kt";
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, rel);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    // ---- destruction -------------------------------------------------

    [Fact]
    public async Task AiPackPins_Destruction_TamperedArtefact_FailsPinnedHash()
    {
        // The fetcher serves tampered bytes for the pack's first
        // file, from the (default) official source. The pinned
        // hash must refuse it and the partial must be deleted.
        var m = AiPackManifest.UiTars15_7B;
        var first = m.Files[0];
        var svc = new AiPackService(m);
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        var tampered = Encoding.UTF8.GetBytes("tampered-artefact-bytes");
        Task Fetch(string url, string dest, CancellationToken ct) =>
            File.WriteAllBytesAsync(dest, tampered, ct);
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch);
        Assert.False(ok);
        Assert.Contains("mismatch", detail, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(dir, first.RelativePath)));
        Assert.False(File.Exists(Path.Combine(dir, first.RelativePath + ".partial")));
    }

    [Fact]
    public async Task AiPackPins_Destruction_ManifestEditedToMatchTampered_FailsIntegrity()
    {
        // Attack: rewrite the first pin to the tampered artefact's
        // hash so the artefact would verify — but leave the
        // manifest digest as captured. The manifest's own integrity
        // protection must refuse before any fetch happens.
        var prod = AiPackManifest.UiTars15_7B;
        var tampered = Encoding.UTF8.GetBytes("tampered-artefact-bytes");
        var editedFiles = prod.Files
            .Select((f, i) => i == 0 ? f with { Sha256 = Sha256Hex(tampered), SizeBytes = tampered.Length } : f)
            .ToList();
        var edited = prod with { Files = editedFiles }; // ManifestDigest deliberately left as captured
        var integrity = edited.ValidateIntegrity();
        Assert.False(integrity.Ok);
        Assert.Contains("integrity", integrity.Detail, StringComparison.OrdinalIgnoreCase);

        var svc = new AiPackService(edited);
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        var fetched = false;
        Task Fetch(string url, string dest, CancellationToken ct)
        { fetched = true; return File.WriteAllBytesAsync(dest, tampered, ct); }
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch);
        Assert.False(ok);
        Assert.Contains("integrity", detail, StringComparison.OrdinalIgnoreCase);
        Assert.False(fetched); // refused before any fetch
        var (vok, vdetail) = await svc.VerifyInstalledAsync(dir);
        Assert.False(vok);
        Assert.Contains("integrity", vdetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AiPackPins_Destruction_TamperedInstalledFile_FailsVerify()
    {
        var good = Encoding.UTF8.GetBytes("genuine-fixture-weights");
        var files = new[] { new PackFile("model.bin", Sha256Hex(good), good.Length) };
        var svc = new AiPackService(AiPackManifest.ForFixture("fixture://local", files));
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        Task Fetch(string url, string dest, CancellationToken ct) => File.WriteAllBytesAsync(dest, good, ct);
        Assert.True((await svc.DownloadAsync(dir, Fetch, fixtureMode: true)).Ok);
        Assert.True((await svc.VerifyInstalledAsync(dir)).Ok);
        await File.WriteAllBytesAsync(Path.Combine(dir, "model.bin"),
            Encoding.UTF8.GetBytes("tampered-after-install"));
        var (ok, detail) = await svc.VerifyInstalledAsync(dir);
        Assert.False(ok);
        Assert.Contains("does not match its pin", detail, StringComparison.OrdinalIgnoreCase);
    }
}
