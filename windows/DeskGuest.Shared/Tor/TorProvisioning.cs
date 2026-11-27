using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Tor;

// =====================================================================
// Tor component provisioning (A2, 2026-11-22) — the `tor` rung's
// missing leg. Until this block, DeskGuest's Tor rung worked only if a
// SOCKS proxy appeared by means outside DeskGuest: no Tor binary was
// pinned, bundled, or provisioned by any setup flow. This file is
// that flow, built to the product's verified-download discipline
// (the AiPack discipline, D25, and the hub-component pin precedent,
// HS-10):
//
//   * The genuine Tor artefact is the Tor Project's OWN expert
//     bundle, pinned the way Headscale is pinned: bundle version +
//     tor version + sha256 of the bundle AND of every file DeskGuest
//     installs from it, in a PACKAGE-MANIFEST
//     (windows-agent/tor-component/) and in code (TorPins below).
//   * The bundle pins were captured 2026-11-22 from the author's
//     own published sha256sums for Tor Browser 16.0.1
//     (dist.torproject.org) and every bundle was downloaded and
//     hash-verified against those sums before its contents were
//     pinned; the extracted binaries were then hashed from the
//     verified bundles. Capture record:
//     windows-agent/proofs/tor-rung-v1/capture-record.md.
//   * The manifest carries an integrity digest over its own pin
//     list (same canonical form family as the AiPack manifest):
//     a pin edited to match a tampered artefact — a downgrade
//     swap — fails ValidateIntegrity and provisioning refuses
//     BEFORE any fetch.
//   * Provisioning verifies size + SHA-256 of the downloaded
//     bundle, then extracts ONLY the pinned files, each verified
//     against its own pin before it lands. Tar entry names are
//     never used as filesystem paths. Any mismatch refuses
//     totally: partials deleted, nothing installed, NO override —
//     a "continue anyway" path does not exist in this API.
//   * The setup act (TorSetupService) is the ONLY writer of the
//     tor.json the rung reads. It re-verifies the installed
//     binary against its pin immediately before EVERY launch —
//     a tampered binary fails verification and is never executed.
//   * The launched client is local-only by construction: the
//     generated torrc opens exactly one listener, a SOCKS port
//     bound to 127.0.0.1. No control port, no OR port, no
//     directory port.
//
// Audit status (D37): the Tor client is an adopted component,
// UNAUDITED in the audit universe; this machinery records that
// and never claims otherwise.
// =====================================================================

/// <summary>One file DeskGuest installs from the expert bundle: its path
/// inside the bundle (also its path under the component home), the
/// pinned SHA-256 of its bytes, and its pinned size.</summary>
public sealed record TorComponentFile(string BundlePath, string Sha256, long SizeBytes);

/// <summary>The pinned expert-bundle artefact for one platform.</summary>
public sealed record TorArtefact(
    string Platform,
    string BundleFileName,
    string BundleSha256,
    long BundleSizeBytes,
    string BinaryBundlePath,
    IReadOnlyList<TorComponentFile> Files);

public sealed record TorComponentManifest(
    string BundleVersion,
    string TorVersion,
    string DownloadBaseUrl,
    IReadOnlyList<TorArtefact> Artefacts,
    string AuditStatus,
    string ManifestDigest)
{
    /// <summary>Canonical manifest digest: SHA-256 (lowercase hex)
    /// of "deskguest-tor-component\n" + BundleVersion + "\n" +
    /// DownloadBaseUrl + "\n" + per artefact (manifest order)
    /// "Platform|BundleFileName|BundleSha256|BundleSizeBytes\n"
    /// followed by per file "BundlePath|sha256-lowercase|SizeBytes\n",
    /// UTF-8. The Kotlin mirror implements the identical form, so
    /// one digest value is valid on both platforms.</summary>
    public static string ComputeManifestDigest(string bundleVersion, string downloadBaseUrl, IReadOnlyList<TorArtefact> artefacts)
    {
        var sb = new StringBuilder();
        sb.Append("deskguest-tor-component\n").Append(bundleVersion).Append('\n').Append(downloadBaseUrl).Append('\n');
        foreach (var a in artefacts)
        {
            sb.Append(a.Platform).Append('|').Append(a.BundleFileName).Append('|')
              .Append(a.BundleSha256.ToLowerInvariant()).Append('|')
              .Append(a.BundleSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
            foreach (var f in a.Files)
                sb.Append(f.BundlePath).Append('|').Append(f.Sha256.ToLowerInvariant()).Append('|')
                  .Append(f.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    /// <summary>The manifest's own integrity protection (the AiPack
    /// discipline): a downgrade swap — a pin edited to match a
    /// tampered artefact — fails the digest; malformed pins,
    /// duplicate or escaping paths, and a binary path that is not
    /// one of the pinned files all fail here. Checked before any
    /// download, extraction, or launch.</summary>
    public (bool Ok, string Detail) ValidateIntegrity()
    {
        if (Artefacts.Count == 0)
            return (false, "tor manifest integrity failure: no artefacts are pinned — refusing");
        var platforms = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in Artefacts)
        {
            if (!platforms.Add(a.Platform))
                return (false, $"tor manifest integrity failure: duplicate artefact for platform '{a.Platform}' — refusing");
            if (a.BundleSha256.Length != 64 || !a.BundleSha256.All(Uri.IsHexDigit))
                return (false, $"tor manifest integrity failure: bundle pin for '{a.Platform}' is not a SHA-256 hex digest — refusing");
            if (a.BundleSizeBytes <= 0)
                return (false, $"tor manifest integrity failure: bundle pin for '{a.Platform}' carries a non-positive size — refusing");
            if (a.BundleFileName.Contains('/') || a.BundleFileName.Contains('\\') || a.BundleFileName.Contains(".."))
                return (false, $"tor manifest integrity failure: bundle file name '{a.BundleFileName}' is not a plain file name — refusing");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var f in a.Files)
            {
                if (f.BundlePath.Contains("..") || Path.IsPathRooted(f.BundlePath) || f.BundlePath.Contains('\\'))
                    return (false, $"tor manifest integrity failure: component file path '{f.BundlePath}' escapes the component home — refusing");
                if (!seen.Add(f.BundlePath))
                    return (false, $"tor manifest integrity failure: duplicate component file path '{f.BundlePath}' — refusing");
                if (f.Sha256.Length != 64 || !f.Sha256.All(Uri.IsHexDigit))
                    return (false, $"tor manifest integrity failure: pin for '{f.BundlePath}' is not a SHA-256 hex digest — refusing");
                if (f.SizeBytes <= 0)
                    return (false, $"tor manifest integrity failure: pin for '{f.BundlePath}' carries a non-positive size — refusing");
            }
            if (!seen.Contains(a.BinaryBundlePath))
                return (false, $"tor manifest integrity failure: the binary path '{a.BinaryBundlePath}' is not one of the pinned files — refusing");
        }
        if (string.IsNullOrWhiteSpace(ManifestDigest))
            return (false, "tor manifest integrity failure: no manifest digest is recorded — refusing");
        var actual = ComputeManifestDigest(BundleVersion, DownloadBaseUrl, Artefacts);
        if (!string.Equals(actual, ManifestDigest, StringComparison.OrdinalIgnoreCase))
            return (false, "tor manifest integrity failure: the manifest digest does not match the pinned artefact list — the manifest has been altered since its pins were captured; refusing");
        return (true, "tor manifest integrity verified");
    }

    public TorArtefact? ForPlatform(string platform) =>
        Artefacts.FirstOrDefault(a => string.Equals(a.Platform, platform, StringComparison.Ordinal));

    /// <summary>The artefact for the platform this process runs on.
    /// Null = no pinned artefact for this platform, which the
    /// provisioner turns into an honest named refusal.</summary>
    public TorArtefact? ForCurrentPlatform()
    {
        if (OperatingSystem.IsWindows()) return ForPlatform(TorPins.WindowsX64);
        if (OperatingSystem.IsLinux()) return ForPlatform(TorPins.LinuxX64);
        return null;
    }

    /// <summary>The production component: the Tor Project's expert
    /// bundle, Tor Browser 16.0.1 / Tor 0.4.9.16, pins captured
    /// 2026-11-22 from the author's own published sums and verified
    /// downloads (see the file header).</summary>
    public static TorComponentManifest Production { get; } = new(
        BundleVersion: TorPins.BundleVersion,
        TorVersion: TorPins.TorVersion,
        DownloadBaseUrl: TorPins.DownloadBaseUrl,
        Artefacts: new TorArtefact[]
        {
            new(TorPins.WindowsX64, "tor-expert-bundle-windows-x86_64-16.0.1.tar.gz",
                "9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b", 23767908L,
                "tor/tor.exe",
                new TorComponentFile[]
                {
                    new("tor/tor.exe", "da22856f95ee24f8ace4ad1ab04acbd818fd6c3042bc3cf8f1d7cc3fa3edcb2b", 10248704L),
                    new("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                    new("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L),
                }),
            new(TorPins.AndroidArm64, "tor-expert-bundle-android-aarch64-16.0.1.tar.gz",
                "0091927b9fd72992a88021d55416b23a8380dc39a70c4b73a2cca9ee6a3dbcec", 19741621L,
                "tor/libTor.so",
                new TorComponentFile[]
                {
                    new("tor/libTor.so", "de31ff6af868c17ce9ddc6519eccecd22eed5e371265d340543ef5c3de7ee293", 6598488L),
                    new("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                    new("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L),
                }),
            new(TorPins.LinuxX64, "tor-expert-bundle-linux-x86_64-16.0.1.tar.gz",
                "7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725", 33731966L,
                "tor/tor",
                new TorComponentFile[]
                {
                    new("tor/tor", "0769509fb10e5b916d91f824fdb7575ae142f5afe134b16e9ea174074a327ccf", 3618712L),
                    new("tor/libcrypto.so.3", "e2c0901c520c07cdaab4af3507bf20f6c80273571764b4dc9b3b0b4a75621052", 5493040L),
                    new("tor/libssl.so.3", "cb31eaf171a10f660137b6c3d1ff552c2e89fdedd20e8523a7bf30cc06727457", 1056448L),
                    new("tor/libevent-2.1.so.7", "d252ad9c63de5ac276bdcf73f466ecf6ce0b390f33c3d241b6a32ea4e2f59ef6", 346424L),
                    new("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                    new("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L),
                }),
        },
        AuditStatus: "unaudited",
        ManifestDigest: "31490c2541096b36500392c69b7dc98e528a87b13e277d107e694fe2f81c7727");

    /// <summary>A same-format fixture manifest (tests only): the
    /// caller supplies an artefact whose pins it computed from the
    /// fixture bytes. Fixture mode is explicit and named — it can
    /// never be confused with the production component.</summary>
    public static TorComponentManifest ForFixture(string baseUrl, TorArtefact artefact) =>
        new("fixture-bundle", "fixture-tor", baseUrl, new[] { artefact }, "unaudited-fixture",
            ComputeManifestDigest("fixture-bundle", baseUrl, new[] { artefact }));
}

/// <summary>The Tor component pins, in code (the hub-component
/// precedent: the PACKAGE-MANIFEST and the code carry the same
/// pins, and the manifest digest binds them).</summary>
public static class TorPins
{
    /// <summary>Tor Browser expert-bundle version — pin, never float.</summary>
    public const string BundleVersion = "16.0.1";
    /// <summary>The Tor version inside the pinned bundle, read from
    /// the verified Linux artefact's own `--version` output at
    /// capture time.</summary>
    public const string TorVersion = "0.4.9.16";
    /// <summary>The author's own distribution directory for the
    /// pinned bundle version — the only source this product will
    /// download the component from.</summary>
    public const string DownloadBaseUrl = "https://dist.torproject.org/torbrowser/16.0.1";
    public const string WindowsX64 = "windows-x86_64";
    public const string AndroidArm64 = "android-aarch64";
    public const string LinuxX64 = "linux-x86_64";
    /// <summary>The DeskGuest-managed Tor client's SOCKS port. Deliberately
    /// not Tor's 9050 or Tor Browser's 9150: those belong to a Tor
    /// the user runs themselves, and DeskGuest never speaks through a
    /// proxy it did not provision and verify.</summary>
    public const int SocksPort = 9160;
    public const string SocksHost = "127.0.0.1";
}

/// <summary>Provisions the pinned Tor component into DeskGuest-managed
/// storage. Fetcher seam: (url, destPath) — production passes the
/// resumable HTTP fetch below; tests pass a fixture fetch. Every
/// refusal is total: nothing partially installs.</summary>
public sealed class TorProvisioner
{
    private readonly TorComponentManifest _manifest;
    public TorProvisioner(TorComponentManifest manifest) => _manifest = manifest;
    public TorComponentManifest Manifest => _manifest;

    public const string InstallRecordFileName = "tor-install.json";

    /// <summary>Download + verify + install the component for
    /// <paramref name="artefact"/> into <paramref name="componentHome"/>.
    /// The bundle is verified (size, then SHA-256) before anything
    /// is extracted; every extracted file is verified against its
    /// own pin before it lands; only pinned files are extracted,
    /// and tar entry names are never used as filesystem paths.</summary>
    public async Task<(bool Ok, string Detail)> ProvisionAsync(
        string componentHome, TorArtefact artefact,
        Func<string, string, CancellationToken, Task> fetcher,
        string? sourceBaseOverride = null, bool fixtureMode = false, CancellationToken ct = default)
    {
        var integrity = _manifest.ValidateIntegrity();
        if (!integrity.Ok) return (false, integrity.Detail);
        var source = sourceBaseOverride ?? _manifest.DownloadBaseUrl;
        if (!fixtureMode && !string.Equals(source, TorPins.DownloadBaseUrl, StringComparison.Ordinal))
            return (false, $"tor: wrong source — the Tor component downloads only from the Tor Project's own distribution directory ({TorPins.DownloadBaseUrl}); '{source}' refused, no override");
        if (fixtureMode && string.Equals(source, TorPins.DownloadBaseUrl, StringComparison.Ordinal))
            return (false, "tor: fixture mode against the production source is refused — fixtures stay local and named");
        Directory.CreateDirectory(componentHome);
        var bundlePath = Path.Combine(componentHome, artefact.BundleFileName + ".partial");
        try { await fetcher(source.TrimEnd('/') + "/" + artefact.BundleFileName, bundlePath, ct); }
        catch (Exception ex)
        {
            TryDelete(bundlePath);
            return (false, $"tor: download of {artefact.BundleFileName} failed ({ex.GetType().Name}) — nothing installed");
        }
        var bundleInfo = new FileInfo(bundlePath);
        if (!bundleInfo.Exists) return (false, $"tor: download of {artefact.BundleFileName} produced no file — nothing installed");
        if (bundleInfo.Length != artefact.BundleSizeBytes)
        {
            TryDelete(bundlePath);
            return (false, $"tor: size mismatch for {artefact.BundleFileName}: pinned {artefact.BundleSizeBytes}, downloaded {bundleInfo.Length} — refused, partial deleted");
        }
        string bundleHash;
        await using (var fs = File.OpenRead(bundlePath))
            bundleHash = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct)).ToLowerInvariant();
        if (!string.Equals(bundleHash, artefact.BundleSha256, StringComparison.OrdinalIgnoreCase))
        {
            TryDelete(bundlePath);
            return (false, $"tor: HASH MISMATCH for {artefact.BundleFileName}: pinned {artefact.BundleSha256}, downloaded {bundleHash} — refused and reported; there is no override");
        }
        // Bundle verified. Extract ONLY the pinned files, each to a
        // staging path, verifying size + hash before it lands.
        var staging = Path.Combine(componentHome, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            var wanted = artefact.Files.ToDictionary(f => f.BundlePath, f => f, StringComparer.Ordinal);
            var extracted = new HashSet<string>(StringComparer.Ordinal);
            await using (var fs = File.OpenRead(bundlePath))
            await using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            using (var tar = new TarReader(gz))
            {
                TarEntry? entry;
                while ((entry = await tar.GetNextEntryAsync(copyData: false, ct)) is not null)
                {
                    if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)) continue;
                    var name = entry.Name.Replace('\\', '/').TrimStart('.', '/');
                    // Match by suffix-tolerant exact pinned path: the
                    // bundle's entries carry no leading "./" in the
                    // pinned release; tolerate one if a re-pack adds it.
                    if (!wanted.TryGetValue(name, out var pin))
                    {
                        // Unpinned entries are never written anywhere.
                        continue;
                    }
                    if (entry.DataStream is null)
                        return RefuseStaging(staging, bundlePath, $"tor: bundle entry '{pin.BundlePath}' carries no data — refused, nothing installed");
                    var stagePath = Path.Combine(staging, pin.BundlePath.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(stagePath)!);
                    await using (var outFs = File.Create(stagePath))
                        await entry.DataStream.CopyToAsync(outFs, ct);
                    var check = await VerifyFileAsync(stagePath, pin, ct);
                    if (!check.Ok) return RefuseStaging(staging, bundlePath, check.Detail);
                    extracted.Add(pin.BundlePath);
                }
            }
            var missing = wanted.Keys.Except(extracted).ToList();
            if (missing.Count > 0)
                return RefuseStaging(staging, bundlePath, $"tor: the verified bundle does not contain the pinned file(s) {string.Join(", ", missing)} — refused, nothing installed");
            // All pinned files verified in staging: land them.
            foreach (var pin in artefact.Files)
            {
                var from = Path.Combine(staging, pin.BundlePath.Replace('/', Path.DirectorySeparatorChar));
                var to = Path.Combine(componentHome, pin.BundlePath.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                File.Move(from, to, overwrite: true);
                if (!OperatingSystem.IsWindows() && pin.BundlePath == artefact.BinaryBundlePath)
                {
                    try { File.SetUnixFileMode(to, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
                    catch { /* mode is a courtesy; the hash is the gate */ }
                }
            }
        }
        finally
        {
            TryDelete(bundlePath);
            try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); } catch { }
        }
        var record = new TorInstallRecord(artefact.Platform, _manifest.BundleVersion, _manifest.TorVersion,
            artefact.BundleSha256, DateTimeOffset.UtcNow);
        await File.WriteAllTextAsync(Path.Combine(componentHome, InstallRecordFileName),
            JsonSerializer.Serialize(record), ct);
        return (true, $"tor: component installed — Tor {_manifest.TorVersion} (expert bundle {_manifest.BundleVersion}, {artefact.Platform}); bundle and {artefact.Files.Count} file(s) verified against the pinned hashes");
    }

    /// <summary>Re-verify the installed binary against its pin.
    /// The setup act calls this immediately before every launch:
    /// a tampered binary fails here and is never executed.</summary>
    public async Task<(bool Ok, string Detail)> VerifyInstalledBinaryAsync(
        string componentHome, TorArtefact artefact, CancellationToken ct = default)
    {
        var integrity = _manifest.ValidateIntegrity();
        if (!integrity.Ok) return (false, integrity.Detail);
        var pin = artefact.Files.First(f => f.BundlePath == artefact.BinaryBundlePath);
        var path = Path.Combine(componentHome, artefact.BinaryBundlePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(path))
            return (false, $"tor: the provisioned Tor binary is missing ({artefact.BinaryBundlePath}) — run Tor setup to provision it");
        return await VerifyFileAsync(path, pin, ct);
    }

    /// <summary>Re-verify EVERY installed component file against
    /// its pin (the pre-run check, mirroring the AiPack wizard's).</summary>
    public async Task<(bool Ok, string Detail)> VerifyInstalledAsync(
        string componentHome, TorArtefact artefact, CancellationToken ct = default)
    {
        var integrity = _manifest.ValidateIntegrity();
        if (!integrity.Ok) return (false, integrity.Detail);
        foreach (var pin in artefact.Files)
        {
            var path = Path.Combine(componentHome, pin.BundlePath.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path)) return (false, $"tor: installed component file {pin.BundlePath} is missing — the component must not run");
            var check = await VerifyFileAsync(path, pin, ct);
            if (!check.Ok) return check;
        }
        return (true, "tor: installed component verified against the pinned hashes");
    }

    private static async Task<(bool Ok, string Detail)> VerifyFileAsync(string path, TorComponentFile pin, CancellationToken ct)
    {
        var info = new FileInfo(path);
        if (info.Length != pin.SizeBytes)
            return (false, $"tor: size mismatch for {pin.BundlePath}: pinned {pin.SizeBytes}, found {info.Length} — refused");
        string actual;
        await using (var fs = File.OpenRead(path))
            actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct)).ToLowerInvariant();
        if (!string.Equals(actual, pin.Sha256, StringComparison.OrdinalIgnoreCase))
            return (false, $"tor: HASH MISMATCH for {pin.BundlePath}: pinned {pin.Sha256}, found {actual} — refused; the file must not be used");
        return (true, "verified");
    }

    private (bool, string) RefuseStaging(string staging, string bundlePath, string detail)
    {
        try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); } catch { }
        TryDelete(bundlePath);
        return (false, detail);
    }

    /// <summary>The production fetcher: HTTPS GET with Range resume.
    /// The pinned bundles are tens of megabytes; a channel that
    /// truncates a long transfer (observed on this product's own
    /// capture run) is resumed, never accepted — the provisioner's
    /// size + hash verification is the only acceptance test, and a
    /// fetch that cannot complete refuses through it.</summary>
    public static async Task HttpFetchResumableAsync(string url, string destPath, CancellationToken ct)
    {
        using var http = new HttpClient();
        long existing = File.Exists(destPath) ? new FileInfo(destPath).Length : 0;
        for (var attempt = 0; attempt < 24; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (existing > 0) req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(existing, null);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (resp.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable) return; // already complete
            resp.EnsureSuccessStatusCode();
            if (existing > 0 && resp.StatusCode == HttpStatusCode.OK)
            {
                // Server ignored the Range header: start over.
                existing = 0;
            }
            var mode = existing > 0 ? FileMode.Append : FileMode.Create;
            await using (var src = await resp.Content.ReadAsStreamAsync(ct))
            await using (var dst = new FileStream(destPath, mode, FileAccess.Write, FileShare.None))
            {
                try { await src.CopyToAsync(dst, ct); }
                catch (IOException) { /* truncated transfer: resume below */ }
                catch (HttpRequestException) { /* truncated transfer: resume below */ }
            }
            var now = File.Exists(destPath) ? new FileInfo(destPath).Length : 0;
            var total = resp.Content.Headers.ContentLength is { } len && resp.StatusCode == HttpStatusCode.PartialContent
                ? existing + len : resp.Content.Headers.ContentLength;
            if (total is null || now >= total) return;
            if (now == existing && attempt > 2)
                throw new IOException("tor download made no progress across resumed attempts");
            existing = now;
        }
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}

/// <summary>What provisioning installed, recorded in the component
/// home. Informational: the pins in code are the authority, and
/// every launch re-verifies against them.</summary>
public sealed record TorInstallRecord(
    string Platform, string BundleVersion, string TorVersion, string BundleSha256, DateTimeOffset InstalledUtc);

/// <summary>The process seam for the DeskGuest-managed Tor client. The
/// Core supplies the real process runner; tests supply a fake that
/// records launches (the destruction proof that a tampered binary
/// is never executed asserts on this seam).</summary>
public interface ITorProcessRunner
{
    bool IsRunning { get; }
    void Start(string binaryPath, string torrcPath, string workingDir);
    void Stop();
}

/// <summary>The Tor setup act (A2 spec): provision if needed,
/// re-verify the installed binary, launch the DeskGuest-managed Tor
/// client as a local-only SOCKS listener, and — only once the
/// SOCKS port answers — write the tor.json the `tor` rung reads.
/// This act is the ONLY writer of tor.json. Every failure is a
/// named refusal and leaves no tor.json behind: an unwritten or
/// removed config is how the rung stays honestly unconfigured.</summary>
public sealed class TorSetupService
{
    private readonly TorProvisioner _provisioner;
    private readonly ITorProcessRunner _process;
    private readonly string _componentHome;
    private readonly string _dataDir;
    private readonly Func<string, int, TimeSpan, CancellationToken, Task<bool>> _socksProbe;

    /// <param name="socksProbe">The SOCKS-readiness probe: given
    /// (host, port, timeout) it answers whether the local SOCKS
    /// listener accepts and greets. Null = the real TCP probe.
    /// Tests substitute it where the environment intercepts
    /// managed loopback connects (this product's sandbox does —
    /// see the A2 ledger fragment); the act's logic is identical
    /// either way, and the production path always uses the real
    /// probe.</param>
    public TorSetupService(TorProvisioner provisioner, ITorProcessRunner process, string componentHome, string dataDir,
        Func<string, int, TimeSpan, CancellationToken, Task<bool>>? socksProbe = null)
    {
        _provisioner = provisioner;
        _process = process;
        _componentHome = componentHome;
        _dataDir = dataDir;
        _socksProbe = socksProbe ?? WaitForSocksAsync;
    }

    public TorComponentManifest Manifest => _provisioner.Manifest;
    public string ComponentHome => _componentHome;
    public bool IsRunning => _process.IsRunning;
    public string TorConfigPath => Path.Combine(_dataDir, "tor.json");

    /// <summary>The generated torrc: exactly one listener, a SOCKS
    /// port on loopback. No control port, no OR port, no directory
    /// port — local-only by construction.</summary>
    public static string BuildTorrc(string componentHome, int socksPort)
    {
        var home = componentHome.Replace('\\', '/');
        var sb = new StringBuilder();
        sb.AppendLine("# DeskGuest-managed Tor client (A2). Generated by DeskGuest Tor setup — do not edit;");
        sb.AppendLine("# the setup act regenerates it on every run.");
        sb.AppendLine($"# Pinned component: Tor {TorPins.TorVersion}, Tor Browser expert bundle {TorPins.BundleVersion}.");
        sb.AppendLine($"SocksPort {TorPins.SocksHost}:{socksPort}");
        sb.AppendLine($"DataDirectory {home}/data");
        sb.AppendLine($"GeoIPFile {home}/data/geoip");
        sb.AppendLine($"GeoIPv6File {home}/data/geoip6");
        sb.AppendLine("ClientOnly 1");
        return sb.ToString();
    }

    /// <summary>Run the setup act end to end. Provisioning uses the
    /// production resumable fetch unless a fixture fetcher is
    /// supplied (tests).</summary>
    public async Task<(bool Ok, string Detail)> RunSetupAsync(
        Func<string, string, CancellationToken, Task>? fetcher = null,
        bool fixtureMode = false, string? sourceBaseOverride = null,
        int socksPort = TorPins.SocksPort, TimeSpan? socksWait = null, CancellationToken ct = default)
    {
        var artefact = _provisioner.Manifest.ForCurrentPlatform();
        if (artefact is null)
            return (false, "tor: no pinned Tor artefact for this platform — Tor setup cannot provision this device");
        var binaryPath = Path.Combine(_componentHome, artefact.BinaryBundlePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(binaryPath))
        {
            var provisioned = await _provisioner.ProvisionAsync(_componentHome, artefact,
                fetcher ?? TorProvisioner.HttpFetchResumableAsync, sourceBaseOverride, fixtureMode, ct);
            if (!provisioned.Ok) return provisioned;
        }
        // Re-verify immediately before launch — every launch, no
        // exceptions. A tampered binary fails here and never runs.
        var verified = await _provisioner.VerifyInstalledBinaryAsync(_componentHome, artefact, ct);
        if (!verified.Ok) return (false, verified.Detail + " — the Tor client was NOT started");
        Directory.CreateDirectory(Path.Combine(_componentHome, "data"));
        var torrcPath = Path.Combine(_componentHome, "torrc");
        await File.WriteAllTextAsync(torrcPath, BuildTorrc(_componentHome, socksPort), ct);
        if (!_process.IsRunning)
        {
            try { _process.Start(binaryPath, torrcPath, _componentHome); }
            catch (Exception ex) { return (false, $"tor: the verified Tor client failed to start ({ex.GetType().Name}) — no Tor configuration written"); }
        }
        if (!await _socksProbe(TorPins.SocksHost, socksPort, socksWait ?? TimeSpan.FromSeconds(60), ct))
        {
            try { _process.Stop(); } catch { }
            TryDelete(TorConfigPath);
            return (false, $"tor: the Tor client did not open its local SOCKS listener on {TorPins.SocksHost}:{socksPort} — no Tor configuration written; the rung stays unconfigured");
        }
        Directory.CreateDirectory(_dataDir);
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["socksHost"] = TorPins.SocksHost,
            ["socksPort"] = socksPort,
        });
        await File.WriteAllTextAsync(TorConfigPath, json, ct);
        return (true, $"tor: DeskGuest-managed Tor client running — local SOCKS proxy at {TorPins.SocksHost}:{socksPort}, binary verified against its pin before launch; tor.json written by Tor setup");
    }

    /// <summary>Stop the DeskGuest-managed client and remove the rung's
    /// configuration, so the rung returns to its honest
    /// unconfigured refusal.</summary>
    public void StopAndUnconfigure()
    {
        try { _process.Stop(); } catch { }
        TryDelete(TorConfigPath);
    }

    /// <summary>Wait until the SOCKS port accepts a TCP connection
    /// and answers a SOCKS5 greeting. Poll only; no traffic beyond
    /// the greeting is sent.</summary>
    private static async Task<bool> WaitForSocksAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var client = new TcpClient();
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(TimeSpan.FromSeconds(2));
                await client.ConnectAsync(host, port, attempt.Token);
                var stream = client.GetStream();
                await stream.WriteAsync(new byte[] { 5, 1, 0 }, attempt.Token);
                var reply = new byte[2];
                var read = 0;
                while (read < 2)
                {
                    var n = await stream.ReadAsync(reply.AsMemory(read), attempt.Token);
                    if (n == 0) break;
                    read += n;
                }
                if (read == 2 && reply[0] == 5 && reply[1] == 0) return true;
            }
            catch { /* not up yet */ }
            await Task.Delay(250, ct);
        }
        return false;
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}
