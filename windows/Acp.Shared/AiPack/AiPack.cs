using System.Security.Cryptography;

namespace Acp.Shared.AiPack;

// =====================================================================
// Local AI pack (D25, Block F). The pack is an OPTIONAL download
// offered by the wizard: UI-TARS-1.5-7B (Apache-2.0) from the
// author's OFFICIAL source only, hash-verified against hashes
// PINNED IN THE PRODUCT, licence shown before download. There is
// NO override on hash mismatch: a mismatch refuses and reports,
// and the partial file is deleted — a "continue anyway" path does
// not exist in this API.
//
// Runtime lane (D9): the downloaded model runs locally behind the
// same MCP/pairing leash as any AI. The pack is an AI participant
// with its own identity (PackUserId), audited under that identity,
// NEVER admin (the roster refuses AI admin seats structurally).
//
// AUDIT STATUS (D37/T7-adjacent, S11): the pack runtime + model
// are UNAUDITED in the audit universe. This machinery records that
// status on the manifest and never claims otherwise.
//
// PIN STATE (A3, 2026-11-22): pins CAPTURED from the author's own
// Hugging Face listing for ByteDance-Seed/UI-TARS-1.5-7B at repo
// commit 683d002dd99d8f95104d31e70391a39348857f4e, via the capture
// tool scripts/aipack_pin_capture.py (agent-control-app/scripts).
// Capture-time verification: every non-LFS file was downloaded
// from the author's resolve endpoint and its git blob SHA-1
// checked against the author's listing oid (pin = SHA-256 of the
// actual bytes); LFS pins are the author's LFS oids (the file's
// SHA-256 by LFS construction). This environment's channel to the
// HF CDN carries LFS payloads at only a few MB/s, so the large
// shards are metadata-pinned, NOT byte-verified — recorded
// per-file in proofs/aipack-pin-capture/capture-record.json and
// byte-verification-remainder.md in the same folder.
// The manifest carries an integrity digest over its own pin list
// (ManifestDigest): editing a pin to match a tampered artefact
// without the digest fails ValidateIntegrity and the download
// refuses before any fetch.
// =====================================================================

public sealed record PackFile(string RelativePath, string Sha256, long SizeBytes);

public sealed record AiPackManifest(
    string PackId,
    string DisplayName,
    string LicenseId,
    string LicenseSummary,
    string OfficialBaseUrl,
    IReadOnlyList<PackFile> Files,
    bool PinsCaptured,
    string AuditStatus,
    string ManifestDigest)
{
    /// <summary>The pack's own AI identity (D9): it pairs and is
    /// audited as this user, never as the human who installed it.</summary>
    public const string PackUserId = "local-ai-pack";

    /// <summary>Canonical manifest digest: SHA-256 (lowercase hex)
    /// of PackId + "\n" + OfficialBaseUrl + "\n" + one
    /// "RelativePath|sha256-lowercase|SizeBytes\n" line per file,
    /// in manifest order, UTF-8. The capture tool and the Kotlin
    /// mirror implement the identical form, so one digest value
    /// is valid on both platforms.</summary>
    public static string ComputeManifestDigest(string packId, string officialBaseUrl, IReadOnlyList<PackFile> files)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(packId).Append('\n').Append(officialBaseUrl).Append('\n');
        foreach (var f in files)
            sb.Append(f.RelativePath).Append('|').Append(f.Sha256.ToLowerInvariant()).Append('|')
              .Append(f.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    /// <summary>The manifest's own integrity protection. A manifest
    /// whose pins were edited (e.g. to match a tampered artefact)
    /// without a matching digest fails here, as does an
    /// inconsistent PinsCaptured flag, a malformed pin, a duplicate
    /// or escaping path. Checked before any download or verify.</summary>
    public (bool Ok, string Detail) ValidateIntegrity()
    {
        if (PinsCaptured != (Files.Count > 0))
            return (false, $"manifest integrity failure: PinsCaptured is {PinsCaptured} but the manifest carries {Files.Count} file(s) — refusing");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in Files)
        {
            if (f.RelativePath.Contains("..") || Path.IsPathRooted(f.RelativePath))
                return (false, $"manifest integrity failure: pack file path '{f.RelativePath}' escapes the pack folder — refusing");
            if (!seen.Add(f.RelativePath))
                return (false, $"manifest integrity failure: duplicate pack file path '{f.RelativePath}' — refusing");
            if (f.Sha256.Length != 64 || !f.Sha256.All(Uri.IsHexDigit))
                return (false, $"manifest integrity failure: pin for '{f.RelativePath}' is not a SHA-256 hex digest — refusing");
            if (f.SizeBytes <= 0)
                return (false, $"manifest integrity failure: pin for '{f.RelativePath}' carries a non-positive size — refusing");
        }
        if (PinsCaptured)
        {
            if (string.IsNullOrWhiteSpace(ManifestDigest))
                return (false, "manifest integrity failure: pins are captured but no manifest digest is recorded — refusing");
            var actual = ComputeManifestDigest(PackId, OfficialBaseUrl, Files);
            if (!string.Equals(actual, ManifestDigest, StringComparison.OrdinalIgnoreCase))
                return (false, "manifest integrity failure: the manifest digest does not match the pinned file list — the manifest has been altered since its pins were captured; refusing");
        }
        return (true, "manifest integrity verified");
    }

    public static AiPackManifest UiTars15_7B { get; } = new(
        PackId: "ui-tars-1.5-7b",
        DisplayName: "UI-TARS-1.5-7B (local AI pack)",
        LicenseId: "Apache-2.0",
        LicenseSummary:
            "Apache License 2.0 — you may use, modify and redistribute this model under the " +
            "Apache-2.0 terms, including the NOTICE and patent-grant terms. The full licence " +
            "text ships with the download (LICENSE file in the author's repository). " +
            "Pack rule (D25): Apache-2.0/MIT checkpoints only.",
        OfficialBaseUrl: "https://huggingface.co/ByteDance-Seed/UI-TARS-1.5-7B/resolve/main",
        Files: new PackFile[]
        {
            new PackFile(".gitattributes", "34448b82c17d60fec9b65b1f093c115ddbaadc04beb1b0140b6bfed2e012a930", 1570L),
            new PackFile("README.md", "fd6ebdc23c119b356e12876c964597d2920e3a2878424a6b5a5b8706e6bc23c4", 8370L),
            new PackFile("added_tokens.json", "58b54bbe36fc752f79a24a271ef66a0a0830054b4dfad94bde757d851968060b", 605L),
            new PackFile("chat_template.json", "ad60d90252ed0b0705ba14e2d0ad0fec0beac1ea955642b54059b36052d8bc96", 1050L),
            new PackFile("config.json", "77d9ec7321cc572e3579e2c84799c9cadaded63c49ce93b101733349fc330c43", 1374L),
            new PackFile("merges.txt", "8831e4f1a044471340f7c0a83d7bd71306a5b867e95fd870f74d0c5308a904d5", 1671853L),
            new PackFile("model-00001-of-00007.safetensors", "791690d15fbd7cb35c5024562a333b6962b4f399e8e00c1d039d516744fd8a9c", 4952311608L),
            new PackFile("model-00002-of-00007.safetensors", "63fdb5528959e72f74516d7e4a5e66337e129428ad49ed82acef03ef648991ca", 4984124272L),
            new PackFile("model-00003-of-00007.safetensors", "8cd4f439df9219991790e0bd557176445165bfcdcae6b98acd4b2a4e70b4adfb", 4932743936L),
            new PackFile("model-00004-of-00007.safetensors", "8cd5267eecb26fd6c77a88cf76a52805b887f2c571c424eb244b97464d3071f2", 4998852296L),
            new PackFile("model-00005-of-00007.safetensors", "68774baed4c0324a411f21b30d3a9e69959f0ac0713eef456dbaaa798d0076d0", 4984124336L),
            new PackFile("model-00006-of-00007.safetensors", "4fce8e78b8af34aa378ab2e6b627711a2527a4de66256d81d444b5e95b956c05", 4932743992L),
            new PackFile("model-00007-of-00007.safetensors", "7b9c3b8638e8cab6cacf3315f2326816ceef2afc0706647d71be37494b462d9c", 3383846800L),
            new PackFile("model.safetensors.index.json", "6030a4a846a2252af2c3cad013ceb7eac26b263bdfa774ce68c151643ca0270e", 57619L),
            new PackFile("preprocessor_config.json", "f2058c716eef96ccaed1cc1e2d0c08306b62586d535b28d9d08e691b2fab7ca0", 350L),
            new PackFile("special_tokens_map.json", "76862e765266b85aa9459767e33cbaf13970f327a0e88d1c65846c2ddd3a1ecd", 613L),
            new PackFile("tokenizer.json", "9c5ae00e602b8860cbd784ba82a8aa14e8feecec692e7076590d014d7b7fdafa", 11421896L),
            new PackFile("tokenizer_config.json", "d8fae64aa6999ec858de2e7e1823f46133514627129f664cc761376c5f520a5e", 7253L),
            new PackFile("vocab.json", "ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910", 2776833L)
        },
        PinsCaptured: true,
        AuditStatus: "unaudited",
        ManifestDigest: "8398a0f9d6cf75e02f48e51226c904425c3d52372cdc56555c5ce9f909fb3157");

    /// <summary>A same-format fixture manifest (tests only): the
    /// caller supplies files whose pins it computed from the
    /// fixture bytes. Fixture mode is explicit and named — it can
    /// never be confused with the production pack.</summary>
    public static AiPackManifest ForFixture(string baseUrl, IReadOnlyList<PackFile> files) =>
        new("fixture-pack", "Fixture pack (test only)", "Apache-2.0",
            "Fixture licence text (test only)", baseUrl, files, PinsCaptured: true, AuditStatus: "unaudited-fixture",
            ManifestDigest: ComputeManifestDigest("fixture-pack", baseUrl, files));
}

public sealed class AiPackService
{
    private readonly AiPackManifest _manifest;
    private bool _licenceAccepted;
    private string? _licenceAcceptedBy;

    public AiPackService(AiPackManifest manifest) => _manifest = manifest;
    public AiPackManifest Manifest => _manifest;
    public bool LicenceAccepted => _licenceAccepted;

    /// <summary>W22: the identity the acceptance is recorded under.
    /// The Core binds this to the host-resolved identity of the
    /// authenticated channel that carried accept_licence — never to
    /// a payload-supplied value (see CoreRuntime.ApplyAiPackAction).</summary>
    public string? LicenceAcceptedBy => _licenceAcceptedBy;

    /// <summary>The wizard step: the licence is SHOWN (this text)
    /// before any download control exists. Acceptance is recorded
    /// against the showing — there is no path that downloads first
    /// and discloses later.</summary>
    public string LicenceToShow() =>
        $"{_manifest.DisplayName}\nLicence: {_manifest.LicenseId}\n{_manifest.LicenseSummary}\n" +
        $"Source (the author's own, the only source this product will use): {_manifest.OfficialBaseUrl}\n" +
        $"Audit status: {_manifest.AuditStatus} (D37 — the pack runtime has not passed an ACP audit).";

    public void AcceptLicence(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) throw new InvalidOperationException("licence acceptance needs the accepting user");
        _licenceAccepted = true;
        _licenceAcceptedBy = userId;
    }

    /// <summary>Download the pack. Fetcher seam: (url, destPath) —
    /// production passes an HttpClient fetch; tests pass a fixture
    /// fetch. Every refusal is total for the file it names: a file
    /// whose bytes fail size/hash verification is deleted and never
    /// lands. W19-C resumability: a file already landed in
    /// <paramref name="targetDir"/> that STILL verifies against its
    /// pin (size + SHA-256, re-checked on every run) is skipped, not
    /// re-fetched — so a cancelled or failed download restarts where
    /// it left off, and a landed file that no longer verifies is
    /// deleted and re-fetched, never trusted. <paramref name="onFileLanded"/>
    /// (optional) reports (landedCount, totalCount, relativePath)
    /// after each file lands or is skip-verified, for progress state.</summary>
    public async Task<(bool Ok, string Detail)> DownloadAsync(
        string targetDir, Func<string, string, CancellationToken, Task> fetcher,
        string? sourceBaseOverride = null, bool fixtureMode = false, CancellationToken ct = default,
        Action<int, int, string>? onFileLanded = null)
    {
        if (!_licenceAccepted)
            return (false, "licence not accepted — the wizard shows the licence before any download (D25)");
        var source = sourceBaseOverride ?? _manifest.OfficialBaseUrl;
        if (!fixtureMode && !string.Equals(source, _manifest.OfficialBaseUrl, StringComparison.Ordinal))
            return (false, $"wrong source — the pack downloads only from the author's official source ({_manifest.OfficialBaseUrl}); '{source}' refused, no override");
        if (fixtureMode && string.Equals(source, AiPackManifest.UiTars15_7B.OfficialBaseUrl, StringComparison.Ordinal))
            return (false, "fixture mode against the production source is refused — fixtures stay local and named");
        // bd-shared-plat-1/F11: fixture mode is a property of the
        // MANIFEST (built by ForFixture), not a caller flag that
        // can be attached to the production manifest — fixtureMode
        // against any non-fixture manifest refused, so the flag
        // can no longer widen the official-source rule.
        if (fixtureMode && !string.Equals(_manifest.PackId, "fixture-pack", StringComparison.Ordinal))
            return (false, "fixture mode is only valid for manifests built by ForFixture — refused for this manifest (the official-source rule has no caller override)");
        var integrity = _manifest.ValidateIntegrity();
        if (!integrity.Ok) return (false, integrity.Detail);
        if (!_manifest.PinsCaptured || _manifest.Files.Count == 0)
            return (false, "no pinned hashes are captured for this pack yet — download refused (a download without a pin to verify against is not offered)");
        Directory.CreateDirectory(targetDir);
        var landed = 0;
        foreach (var file in _manifest.Files)
        {
            if (file.RelativePath.Contains("..") || Path.IsPathRooted(file.RelativePath))
                return (false, $"pack file path '{file.RelativePath}' escapes the pack folder — refused");
            var dest = Path.Combine(targetDir, file.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            // W19-C resume: a previously landed file counts only if
            // it STILL verifies against its pin right now.
            if (File.Exists(dest))
            {
                var prior = new FileInfo(dest);
                string priorHash = "";
                if (prior.Length == file.SizeBytes)
                {
                    await using var pfs = File.OpenRead(dest);
                    priorHash = Convert.ToHexString(await SHA256.HashDataAsync(pfs, ct)).ToLowerInvariant();
                }
                if (prior.Length == file.SizeBytes &&
                    string.Equals(priorHash, file.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    landed++;
                    onFileLanded?.Invoke(landed, _manifest.Files.Count, file.RelativePath);
                    continue;
                }
                TryDelete(dest); // landed bytes that no longer verify are never trusted — re-fetch
            }
            var partial = dest + ".partial";
            try { await fetcher(source.TrimEnd('/') + "/" + file.RelativePath, partial, ct); }
            catch (Exception ex)
            {
                TryDelete(partial);
                return (false, $"download of {file.RelativePath} failed ({ex.GetType().Name}) — nothing installed");
            }
            var info = new FileInfo(partial);
            if (!info.Exists) return (false, $"download of {file.RelativePath} produced no file — nothing installed");
            if (info.Length != file.SizeBytes)
            { TryDelete(partial); return (false, $"size mismatch for {file.RelativePath}: expected {file.SizeBytes}, got {info.Length} — refused, partial deleted"); }
            string actual;
            await using (var fs = File.OpenRead(partial))
                actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct)).ToLowerInvariant();
            if (!string.Equals(actual, file.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(partial);
                return (false, $"HASH MISMATCH for {file.RelativePath}: pinned {file.Sha256}, downloaded {actual} — refused and reported; there is no override");
            }
            File.Move(partial, dest, overwrite: true);
            landed++;
            onFileLanded?.Invoke(landed, _manifest.Files.Count, file.RelativePath);
        }
        return (true, $"pack installed: {_manifest.Files.Count} file(s), every hash verified against the pinned hashes");
    }

    /// <summary>Re-verify an installed pack against the pins (the
    /// wizard's post-install and pre-run check).</summary>
    public async Task<(bool Ok, string Detail)> VerifyInstalledAsync(string targetDir, CancellationToken ct = default)
    {
        var integrity = _manifest.ValidateIntegrity();
        if (!integrity.Ok) return (false, integrity.Detail);
        if (!_manifest.PinsCaptured) return (false, "no pins captured — nothing can be verified");
        foreach (var file in _manifest.Files)
        {
            var path = Path.Combine(targetDir, file.RelativePath);
            if (!File.Exists(path)) return (false, $"missing pack file {file.RelativePath}");
            string actual;
            await using var fs = File.OpenRead(path);
            actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct)).ToLowerInvariant();
            if (!string.Equals(actual, file.Sha256, StringComparison.OrdinalIgnoreCase))
                return (false, $"installed file {file.RelativePath} does not match its pin — the pack must not run");
        }
        return (true, "installed pack verified against the pinned hashes");
    }

    /// <summary>The production fetcher: plain HTTPS GET to disk.
    /// Used only with the official source (enforced above).
    /// bd-shared-plat-1/F11: when the caller knows the pinned size
    /// it passes it as <paramref name="maxBytes"/> and the stream
    /// is cut the moment it exceeds it — an endless/oversize body
    /// is never buffered to disk in full before the size check.</summary>
    public static async Task HttpFetchAsync(string url, string destPath, CancellationToken ct, long maxBytes = -1)
    {
        using var http = new HttpClient();
        using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        if (maxBytes >= 0 && resp.Content.Headers.ContentLength is { } declared && declared > maxBytes)
            throw new InvalidOperationException($"response declares {declared} bytes, over the pinned size {maxBytes} — refused before streaming");
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = File.Create(destPath);
        if (maxBytes < 0) { await src.CopyToAsync(dst, ct); return; }
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await src.ReadAsync(buffer, ct)) > 0)
        {
            total += read;
            if (total > maxBytes)
                throw new InvalidOperationException($"response exceeded the pinned size {maxBytes} mid-stream — download cut");
            await dst.WriteAsync(buffer.AsMemory(0, read), ct);
        }
    }

    /// <summary>The production fetcher for the pack download
    /// (W19-C): HTTPS GET with Range resume, the Tor provisioner's
    /// discipline. The pack's shards are gigabytes; a channel that
    /// truncates a long transfer is resumed against the surviving
    /// .partial, never accepted — DownloadAsync's size + SHA-256
    /// verification against the pins is the only acceptance test,
    /// and a fetch that cannot complete refuses through it.
    /// Cancellation deletes nothing here: the caller (DownloadAsync)
    /// owns the partial's fate on a failed/cancelled fetch.</summary>
    public static async Task HttpFetchResumableAsync(string url, string destPath, CancellationToken ct)
    {
        using var http = new HttpClient();
        long existing = File.Exists(destPath) ? new FileInfo(destPath).Length : 0;
        for (var attempt = 0; attempt < 32; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (existing > 0) req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(existing, null);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (resp.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable) return; // already complete
            resp.EnsureSuccessStatusCode();
            if (existing > 0 && resp.StatusCode == System.Net.HttpStatusCode.OK)
            {
                // Server ignored the Range header: start over.
                existing = 0;
            }
            var mode = existing > 0 ? FileMode.Append : FileMode.Create;
            await using (var src = await resp.Content.ReadAsStreamAsync(ct))
            await using (var dst = new FileStream(destPath, mode, FileAccess.Write, FileShare.None))
            {
                try { await src.CopyToAsync(dst, ct); }
                catch (IOException) { if (ct.IsCancellationRequested) throw; /* truncated transfer: resume below */ }
                catch (HttpRequestException) { if (ct.IsCancellationRequested) throw; /* truncated transfer: resume below */ }
            }
            var now = File.Exists(destPath) ? new FileInfo(destPath).Length : 0;
            var total = resp.Content.Headers.ContentLength is { } len && resp.StatusCode == System.Net.HttpStatusCode.PartialContent
                ? existing + len : resp.Content.Headers.ContentLength;
            if (total is null || now >= total) return;
            if (now == existing && attempt > 2)
                throw new IOException("aipack download made no progress across resumed attempts");
            existing = now;
        }
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}
