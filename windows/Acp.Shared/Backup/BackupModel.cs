using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.ManagementPolicy;

namespace Acp.Shared.Backup;

// =====================================================================
// RMM-06 — Endpoint backup to user-owned storage: file/folder +
// image, immutable, monitored. MODEL LAYER: storage targets, policy
// content, capture contracts, snapshot/manifest records, raw storage.
//
// Doctrine carried from the register:
//   * Storage is storage the USER owns — the hub, a NAS, a site
//     server, a local disk. ACP's own target types are exactly those
//     four; a target that resolves to a vendor-cloud endpoint is
//     REFUSED BY SHAPE (BackupStorageTarget.Validate). Named
//     honestly: the product cannot police what a user mounts at a
//     path — but ACP will not itself name a cloud endpoint a target.
//   * The product meters nothing. Usage reporting (BackupEngine) is
//     truthful accounting from the catalogue, never billing data.
//   * Capture is agent-side behind interfaces. VSS on Windows is
//     the production shape (IVolumeShadowCopyProvider); tests drive
//     fakes. No code in this lane snapshots a real disk.
//   * DIR-45 note: the hub's own backup is a documented DR
//     procedure, not code machinery in this tree — there is no hub
//     backup store to reuse. What this lane reuses is the
//     discipline the hub machinery established: hash-chained
//     records (ChainedAuditLog pattern), temp+replace persistence,
//     content addressing (RMM-14), and verify-before-trust.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-06. The feature toggle
/// itself is seeded in the RMM-07 registry (`rmm.backup.enabled`,
/// default ON); these are the policy-content key shapes.</summary>
public static class BackupPolicyKeys
{
    public const string BackupEnabled = "rmm.backup.enabled";
    public const string JobsList = "backup.jobs";                       // comma-separated job ids
    public const string TargetsList = "backup.targets";                 // comma-separated target ids
    public static string JobKey(string jobId, string field) => $"backup.job.{jobId}.{field}";
    public static string TargetKey(string targetId, string field) => $"backup.target.{targetId}.{field}";
}

/// <summary>Backup kinds. A kind outside this set refuses — an
/// unknown kind is a field that changes meaning.</summary>
public static class BackupKinds
{
    public const string File = "file";
    public const string Image = "image";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { File, Image };
}

/// <summary>Storage target kinds — the ONLY target types ACP has.
/// There is deliberately no "cloud" kind.</summary>
public static class BackupTargetKinds
{
    public const string Hub = "hub";
    public const string Nas = "nas";
    public const string SiteServer = "site_server";
    public const string Local = "local";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Hub, Nas, SiteServer, Local };
}

/// <summary>One user-owned storage target. The locator's shape is
/// kind-specific: hub → the hub's device id; local → an absolute
/// path; nas/site_server → a UNC path (\\host\share) or smb:// URI.</summary>
public sealed record BackupStorageTarget(string Id, string Kind, string Locator)
{
    /// <summary>Host suffixes that name vendor-cloud storage. A
    /// target resolving to one of these is a vendor cloud wearing a
    /// NAS costume — refused by shape.</summary>
    private static readonly string[] VendorCloudSuffixes =
    {
        "amazonaws.com", "blob.core.windows.net", "file.core.windows.net",
        "queue.core.windows.net", "table.core.windows.net",
        "storage.googleapis.com", "dropbox.com", "dropboxapi.com",
        "backblazeb2.com", "wasabisys.com", "digitaloceanspaces.com",
        "s3.amazonaws.com",
    };

    /// <summary>Absolute-path shape, judged by SHAPE not by the
    /// host OS's Path rules: the product runs on Windows, so a
    /// drive-qualified path (C:\...) is absolute whatever OS the
    /// validator happens to execute on; rooted POSIX and UNC
    /// shapes count too.</summary>
    public static bool IsAbsolutePathShape(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Trim();
        if (p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) return true;
        if (p.StartsWith(@"\\")) return true;
        return Path.IsPathFullyQualified(p);
    }

    /// <summary>D38 F5: normalise a locator host before the
    /// vendor-cloud suffix check — strip a port (`host:445`), a
    /// trailing dot (`host.`), and a WebDAV `@SSL`/`@443` suffix, and
    /// lower-case. Without this, `acct.file.core.windows.net:445`,
    /// `x.blob.core.windows.net.` and `bucket.s3.amazonaws.com@SSL`
    /// all walked past the suffix loop (Azure Files really is SMB
    /// on 445, so these are live paths, not spelling trivia).</summary>
    public static string NormaliseHost(string? host)
    {
        var h = (host ?? "").Trim().ToLowerInvariant();
        var at = h.IndexOf('@');
        if (at >= 0) h = h[..at];
        var colon = h.IndexOf(':');
        if (colon >= 0) h = h[..colon];
        return h.TrimEnd('.');
    }

    /// <summary>The host named by a UNC (\\host\share) or smb://
    /// locator, normalised; null when the locator names no host.</summary>
    public static string? ExtractHost(string loc)
    {
        string raw;
        if (loc.StartsWith(@"\\")) raw = loc[2..].Split('\\', '/')[0];
        else if (loc.StartsWith("smb://", StringComparison.OrdinalIgnoreCase)) raw = loc[6..].Split('/')[0];
        else return null;
        var h = NormaliseHost(raw);
        return h.Length == 0 ? null : h;
    }

    public static bool IsVendorCloudHost(string? host)
    {
        var h = NormaliseHost(host);
        if (h.Length == 0) return false;
        return VendorCloudSuffixes.Any(suffix =>
            h.Equals(suffix, StringComparison.Ordinal) || h.EndsWith("." + suffix, StringComparison.Ordinal));
    }

    /// <summary>Null when the target is admissible; otherwise the
    /// refusal reason. Fail-closed on every ambiguity.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id)) return "backup target needs an id — refused";
        if (!BackupTargetKinds.All.Contains(Kind ?? ""))
            return $"unknown backup target kind '{Kind}' — refused (ACP target types are hub, nas, site_server, local only)";
        if (string.IsNullOrWhiteSpace(Locator)) return $"backup target '{Id}' carries no locator — refused";
        var loc = Locator.Trim();

        // Any explicit remote-object scheme is a vendor-cloud shape,
        // whatever kind the target claims to be.
        foreach (var scheme in new[] { "http://", "https://", "s3://", "gs://", "az://", "azure://" })
            if (loc.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                return $"backup target '{Id}' locator '{loc}' uses remote-object scheme '{scheme.TrimEnd(':', '/')}' — REFUSED: ACP backs up to storage the user owns (hub, NAS, site server, local disk), never a vendor cloud";

        // D38 F5: the vendor-cloud host check applies to EVERY kind
        // whose locator names a host — including kind=local with a
        // UNC locator, which previously returned before any host
        // check ran.
        if (ExtractHost(loc) is { } anyHost && IsVendorCloudHost(anyHost))
            return $"backup target '{Id}' host '{anyHost}' is a vendor-cloud endpoint dressed as a {Kind} — REFUSED: ACP target types are user-owned storage only";

        switch (Kind)
        {
            case BackupTargetKinds.Local:
                if (!IsAbsolutePathShape(loc))
                    return $"local backup target '{Id}' locator '{loc}' is not an absolute path — refused";
                return null;
            case BackupTargetKinds.Hub:
                if (loc.Contains("://") || loc.Contains('\\') || loc.Contains('/'))
                    return $"hub backup target '{Id}' locator '{loc}' is not a hub device id — refused";
                return null;
            case BackupTargetKinds.Nas:
            case BackupTargetKinds.SiteServer:
            {
                var host = ExtractHost(loc);
                if (host is null)
                {
                    if (loc.StartsWith(@"\\") || loc.StartsWith("smb://", StringComparison.OrdinalIgnoreCase))
                        return $"backup target '{Id}' locator '{loc}' names no host — refused";
                    return $"backup target '{Id}' locator '{loc}' is neither a UNC path (\\\\host\\share) nor an smb:// URI — refused";
                }
                return null; // vendor-cloud hosts already refused above, for every kind
            }
            default:
                return $"unknown backup target kind '{Kind}' — refused";
        }
    }
}

/// <summary>How often a job runs. Interval-based: due when the last
/// attempt is at least IntervalHours old (or never happened).</summary>
public sealed record BackupSchedule(int IntervalHours)
{
    public bool IsDue(DateTimeOffset? lastAttemptUtc, DateTimeOffset now) =>
        lastAttemptUtc is null || now - lastAttemptUtc.Value >= TimeSpan.FromHours(Math.Max(1, IntervalHours));

    public DateTimeOffset NextDue(DateTimeOffset? lastAttemptUtc) =>
        lastAttemptUtc is null ? DateTimeOffset.MinValue : lastAttemptUtc.Value + TimeSpan.FromHours(Math.Max(1, IntervalHours));
}

/// <summary>One backup job — POLICY CONTENT (RMM-07): schedule,
/// selection, retention and target all arrive as management-policy
/// settings and are computed through Effective Policy, so a fleet
/// change is one policy edit. RetentionDays has a hard floor of 1:
/// a zero-retention "immutable" backup is a contradiction, and the
/// parser refuses it rather than honouring it.</summary>
public sealed record BackupJobDefinition(
    string Id,
    string DeviceId,
    string OwnerUserId,
    string Kind,
    IReadOnlyList<string> Selection,
    string TargetId,
    BackupSchedule Schedule,
    int RetentionDays,
    bool Enabled)
{
    public const int MinRetentionDays = 1;

    public IReadOnlyList<string> Selection { get; init; } = Selection ?? Array.Empty<string>();
}

/// <summary>Parses backup jobs + targets out of an Effective Policy
/// settings tree. Malformed content refuses BY NAME (the refusal is
/// returned, never thrown, never silently dropped): one bad job
/// does not take the well-formed jobs down with it, but it is never
/// invisible either.</summary>
public static class BackupPolicyContent
{
    public sealed record ParseResult(
        IReadOnlyList<BackupJobDefinition> Jobs,
        IReadOnlyList<BackupStorageTarget> Targets,
        IReadOnlyList<string> Refusals);

    public static ParseResult Parse(EffectivePolicy effective)
    {
        var refusals = new List<string>();
        var targets = new List<BackupStorageTarget>();
        var jobs = new List<BackupJobDefinition>();

        string? Get(string key) => effective.Get(key)?.Value;

        foreach (var targetId in SplitList(Get(BackupPolicyKeys.TargetsList)))
        {
            var kind = Get(BackupPolicyKeys.TargetKey(targetId, "kind"))?.Trim().ToLowerInvariant() ?? "";
            var locator = Get(BackupPolicyKeys.TargetKey(targetId, "locator")) ?? "";
            var target = new BackupStorageTarget(targetId, kind, locator);
            if (target.Validate() is { } refusal) { refusals.Add(refusal); continue; }
            targets.Add(target);
        }
        var targetIds = new HashSet<string>(targets.Select(t => t.Id), StringComparer.OrdinalIgnoreCase);

        foreach (var jobId in SplitList(Get(BackupPolicyKeys.JobsList)))
        {
            string F(string field) => Get(BackupPolicyKeys.JobKey(jobId, field)) ?? "";
            var kind = F("kind").Trim().ToLowerInvariant();
            var device = F("device").Trim();
            var owner = F("owner").Trim();
            var targetId = F("target").Trim();
            var selection = F("selection").Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
            if (!BackupKinds.All.Contains(kind)) { refusals.Add($"backup job '{jobId}' names unknown kind '{kind}' — refused"); continue; }
            if (device.Length == 0) { refusals.Add($"backup job '{jobId}' names no device — refused"); continue; }
            if (owner.Length == 0) { refusals.Add($"backup job '{jobId}' names no owner user — refused (self-restore scoping needs an owner)"); continue; }
            if (selection.Count == 0) { refusals.Add($"backup job '{jobId}' selects nothing — refused (a backup of nothing is not a backup)"); continue; }
            if (!targetIds.Contains(targetId)) { refusals.Add($"backup job '{jobId}' names unknown or refused target '{targetId}' — refused"); continue; }
            if (!int.TryParse(F("interval_hours"), out var interval) || interval < 1)
            { refusals.Add($"backup job '{jobId}' has no valid interval_hours (>= 1) — refused"); continue; }
            if (!int.TryParse(F("retention_days"), out var retention) || retention < BackupJobDefinition.MinRetentionDays)
            { refusals.Add($"backup job '{jobId}' retention_days '{F("retention_days")}' is below the {BackupJobDefinition.MinRetentionDays}-day immutability floor — refused"); continue; }
            var enabledRaw = F("enabled");
            var enabled = enabledRaw.Length == 0 || !bool.TryParse(enabledRaw, out var en) ? true : en;
            if (enabledRaw.Length > 0 && !bool.TryParse(enabledRaw, out _))
            { refusals.Add($"backup job '{jobId}' enabled value '{enabledRaw}' is not a boolean — refused"); continue; }
            jobs.Add(new BackupJobDefinition(jobId, device, owner, kind, selection, targetId,
                new BackupSchedule(interval), retention, enabled));
        }
        return new ParseResult(jobs, targets, refusals);
    }

    private static IEnumerable<string> SplitList(string? value) =>
        (value ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}

// ---- capture -----------------------------------------------------------

/// <summary>One captured file: a RELATIVE path (never rooted, never
/// carrying traversal — enforced again at seal and restore) and its
/// bytes. Image captures prefix paths with the volume id
/// ("vol-&lt;id&gt;/...") so an image's contents browse exactly like
/// a file set.</summary>
public sealed record CapturedItem(string RelativePath, byte[] Content);

/// <summary>One volume in an image capture: the layout a bare-metal
/// restore plan is built from.</summary>
public sealed record VolumeDescriptor(
    string VolumeId, long SizeBytes, string FileSystem, int PartitionIndex, bool IsBoot, bool IsSystem);

/// <summary>The result of one capture pass. Notes name what could
/// not be read — a capture that silently skips files is a backup
/// that lies, so gaps travel with the result and into the run
/// record.</summary>
public sealed record CaptureResult(
    string Kind,
    IReadOnlyList<CapturedItem> Items,
    IReadOnlyList<VolumeDescriptor> Volumes,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<CapturedItem> Items { get; init; } = Items ?? Array.Empty<CapturedItem>();
    public IReadOnlyList<VolumeDescriptor> Volumes { get; init; } = Volumes ?? Array.Empty<VolumeDescriptor>();
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
    public long TotalBytes => Items.Sum(i => (long)i.Content.Length);
}

/// <summary>The agent-side capture contract. Implementations read
/// the job's selection and return its contents; throwing is a
/// failed capture, named as such by the engine. The production
/// implementation on Windows captures through a VSS snapshot (see
/// IVolumeShadowCopyProvider) so open files copy consistently;
/// tests drive FakeBackupCaptureSource. NO implementation in this
/// lane touches a real disk.</summary>
public interface IBackupCaptureSource
{
    CaptureResult Capture(BackupJobDefinition job, DateTimeOffset now);
}

/// <summary>The VSS production seam: create a shadow copy of the
/// given volumes, read through its device paths, dispose to release.
/// Host wiring implements this against the Windows VSS APIs; the
/// engine never sees it — capture sources do.</summary>
public interface IVolumeShadowCopyProvider
{
    IDisposable CreateSnapshot(IReadOnlyList<string> volumes);
    string SnapshotDevicePath(string volume);
}

/// <summary>The honest stand-in until host wiring lands: VSS is not
/// available, and says so by name instead of capturing live files
/// and pretending they were snapshot-consistent.</summary>
public sealed class UnavailableVssProvider : IVolumeShadowCopyProvider
{
    public IDisposable CreateSnapshot(IReadOnlyList<string> volumes) =>
        throw new InvalidOperationException("VSS shadow copies are Windows host wiring and are not available in this build — capture refuses rather than reading live files under a snapshot claim");
    public string SnapshotDevicePath(string volume) =>
        throw new InvalidOperationException("VSS shadow copies are Windows host wiring and are not available in this build");
}

/// <summary>Scripted capture double (house pattern: fakes live
/// beside the model). File contents are keyed by the exact selection
/// path; image captures carry a volume layout plus volume-prefixed
/// items. Can be scripted to throw (a dead capture agent) or to
/// return nothing (the success-while-writing-nothing attack).</summary>
public sealed class FakeBackupCaptureSource : IBackupCaptureSource
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<VolumeDescriptor> _volumes = new();
    private Exception? _throw;

    public int CallCount { get; private set; }

    public FakeBackupCaptureSource AddFile(string path, string content)
    {
        _files[path] = Encoding.UTF8.GetBytes(content);
        return this;
    }

    public FakeBackupCaptureSource AddFileBytes(string path, byte[] content)
    {
        _files[path] = content;
        return this;
    }

    public FakeBackupCaptureSource AddVolume(VolumeDescriptor volume, params (string Path, string Content)[] files)
    {
        _volumes.Add(volume);
        foreach (var (path, content) in files)
            _files[$"vol-{volume.VolumeId}/{path.Replace('\\', '/')}"] = Encoding.UTF8.GetBytes(content);
        return this;
    }

    public FakeBackupCaptureSource ThenThrow(Exception ex) { _throw = ex; return this; }

    public CaptureResult Capture(BackupJobDefinition job, DateTimeOffset now)
    {
        CallCount++;
        if (_throw is not null) throw _throw;
        var items = new List<CapturedItem>();
        var notes = new List<string>();
        if (job.Kind == BackupKinds.Image)
        {
            foreach (var vol in _volumes)
                foreach (var (path, bytes) in _files)
                    if (path.StartsWith($"vol-{vol.VolumeId}/", StringComparison.OrdinalIgnoreCase))
                        items.Add(new CapturedItem(path, bytes));
            if (_volumes.Count == 0) notes.Add("no volumes in fake image source");
            return new CaptureResult(BackupKinds.Image, items, _volumes.ToList(), notes);
        }
        foreach (var sel in job.Selection)
        {
            if (_files.TryGetValue(sel, out var bytes))
                items.Add(new CapturedItem(NormaliseRelative(sel), bytes));
            else
                notes.Add($"not_read:{sel}");
        }
        return new CaptureResult(BackupKinds.File, items, Array.Empty<VolumeDescriptor>(), notes);
    }

    /// <summary>A selection path like "C:\data\a.txt" becomes the
    /// manifest-relative "C/data/a.txt" — rooted selections are
    /// stored relative to their root so a manifest never carries an
    /// absolute restore instruction.</summary>
    public static string NormaliseRelative(string path)
    {
        var p = path.Replace('\\', '/').Trim();
        if (p.Length >= 2 && p[1] == ':') p = p[0] + "/" + p[2..].TrimStart('/');
        return p.TrimStart('/');
    }
}

// ---- snapshot / manifest records ----------------------------------------

/// <summary>One file inside a snapshot: its manifest-relative path,
/// size, whole-file SHA-256, and the content-addressed chunks it
/// was split into (each chunk's SHA-256 IS its storage key).</summary>
public sealed record BackupManifestEntry(
    string Path, long SizeBytes, string FileHash, IReadOnlyList<string> ChunkHashes);

/// <summary>A snapshot's manifest: everything restore needs and
/// everything poisoning must defeat. The manifest's own hash covers
/// the canonical JSON of its entries + volume layout; restore
/// re-verifies every file against it before writing a byte.</summary>
public sealed record BackupManifest(
    string SnapshotId, string JobId, string DeviceId, string OwnerUserId,
    string Kind, IReadOnlyList<BackupManifestEntry> Entries,
    IReadOnlyList<VolumeDescriptor> Volumes)
{
    public long TotalBytes => Entries.Sum(e => e.SizeBytes);

    public string CanonicalJson() => JsonSerializer.Serialize(new
    {
        snapshotId = SnapshotId, jobId = JobId, deviceId = DeviceId, ownerUserId = OwnerUserId, kind = Kind,
        entries = Entries.OrderBy(e => e.Path, StringComparer.Ordinal)
            .Select(e => new { path = e.Path, size = e.SizeBytes, hash = e.FileHash, chunks = e.ChunkHashes }).ToArray(),
        volumes = Volumes.OrderBy(v => v.PartitionIndex)
            .Select(v => new { id = v.VolumeId, size = v.SizeBytes, fs = v.FileSystem, part = v.PartitionIndex, boot = v.IsBoot, sys = v.IsSystem }).ToArray(),
    });

    public string ComputeHash() => BackupHashing.Sha256Hex(CanonicalJson());
}

public static class BackupHashing
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    public static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}

/// <summary>Snapshot lifecycle. Sealed is the only state a restore
/// or a purge decision may touch; a sealed snapshot's bytes and
/// manifest NEVER change — the store exposes no mutation path.</summary>
public static class SnapshotStates
{
    public const string Capturing = "capturing";
    public const string Sealed = "sealed";
    public const string Purged = "purged";
}

/// <summary>One catalogue record for a snapshot. CatalogueHash
/// chains each record to its predecessor (ChainedAuditLog pattern):
/// rewriting history — extending a retention, swapping a manifest
/// hash, deleting a record — breaks the chain and the catalogue
/// imports as TAMPERED, which refuses restores and purges.</summary>
public sealed record BackupSnapshot(
    string Id, string JobId, string DeviceId, string OwnerUserId, string TargetId,
    string Kind, string State,
    DateTimeOffset CapturedUtc, DateTimeOffset? SealedUtc, DateTimeOffset? RetentionExpiresUtc,
    string ManifestHash, long TotalBytes, int FileCount,
    string PrevCatalogueHash, string CatalogueHash)
{
    public bool IsSealed => State == SnapshotStates.Sealed;
    public bool IsLocked(DateTimeOffset now) =>
        IsSealed && RetentionExpiresUtc is { } exp && now < exp;
}

// ---- raw storage ---------------------------------------------------------

/// <summary>The raw byte store under the snapshot store: named
/// blobs in, named blobs out. This layer knows nothing about
/// immutability — ALL lock discipline lives in BackupSnapshotStore,
/// which is the only caller production code uses. Keys are
/// store-relative ("chunks/&lt;hash&gt;", "manifests/&lt;id&gt;")
/// and are validated against traversal by every implementation.</summary>
public interface IBackupStorage
{
    void Put(string key, byte[] bytes);
    byte[]? Get(string key);
    bool Exists(string key);
    IReadOnlyList<string> ListKeys(string prefix);
    void Delete(string key);
    long? FreeBytes { get; }
}

internal static class StorageKeyGuard
{
    public static string Check(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) throw new ArgumentException("storage key is empty", nameof(key));
        var k = key.Replace('\\', '/');
        if (k.StartsWith('/') || k.Contains("..") || (k.Length >= 2 && k[1] == ':'))
            throw new ArgumentException($"storage key '{key}' escapes the store — refused", nameof(key));
        return k;
    }
}

/// <summary>In-memory raw storage (tests + the hub-target shape
/// exercised without a disk).</summary>
public sealed class InMemoryBackupStorage : IBackupStorage
{
    private readonly Dictionary<string, byte[]> _blobs = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public long? FreeBytes => null; // unbounded test double — reports unknown, never a fake number

    public void Put(string key, byte[] bytes)
    {
        var k = StorageKeyGuard.Check(key);
        lock (_gate) _blobs[k] = bytes.ToArray();
    }

    public byte[]? Get(string key)
    {
        var k = StorageKeyGuard.Check(key);
        lock (_gate) return _blobs.TryGetValue(k, out var b) ? b.ToArray() : null;
    }

    public bool Exists(string key)
    {
        var k = StorageKeyGuard.Check(key);
        lock (_gate) return _blobs.ContainsKey(k);
    }

    public IReadOnlyList<string> ListKeys(string prefix)
    {
        var p = StorageKeyGuard.Check(prefix);
        lock (_gate) return _blobs.Keys.Where(k => k.StartsWith(p, StringComparison.Ordinal))
            .OrderBy(k => k, StringComparer.Ordinal).ToList();
    }

    public void Delete(string key)
    {
        var k = StorageKeyGuard.Check(key);
        lock (_gate) _blobs.Remove(k);
    }
}

/// <summary>Directory-backed raw storage: one file per key under a
/// root the target names. This is the NAS/local/hub shape exercised
/// against a temp directory in tests — it is a storage TARGET, not
/// a capture of any real disk.</summary>
public sealed class DirectoryBackupStorage : IBackupStorage
{
    private readonly string _root;

    public DirectoryBackupStorage(string root)
    {
        if (!Path.IsPathFullyQualified(root ?? ""))
            throw new ArgumentException("directory storage root must be an absolute path", nameof(root));
        _root = root!;
        Directory.CreateDirectory(_root);
    }

    public string Root => _root;

    private string FullPath(string key)
    {
        var k = StorageKeyGuard.Check(key);
        var full = Path.GetFullPath(Path.Combine(_root, k.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(Path.GetFullPath(_root) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException($"storage key '{key}' escapes the store root — refused", nameof(key));
        return full;
    }

    public void Put(string key, byte[] bytes)
    {
        var full = FullPath(key);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var tmp = full + ".tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, full, overwrite: true);
    }

    public byte[]? Get(string key)
    {
        var full = FullPath(key);
        return File.Exists(full) ? File.ReadAllBytes(full) : null;
    }

    public bool Exists(string key) => File.Exists(FullPath(key));

    public IReadOnlyList<string> ListKeys(string prefix)
    {
        var p = StorageKeyGuard.Check(prefix);
        if (!Directory.Exists(_root)) return Array.Empty<string>();
        // D38 F12: enumerate only the subtree the prefix names —
        // the health probe's ListKeys("chunks/") previously walked
        // the WHOLE storage tree on every call.
        var slash = p.LastIndexOf('/');
        var baseDir = slash >= 0
            ? Path.GetFullPath(Path.Combine(_root, p[..slash].Replace('/', Path.DirectorySeparatorChar)))
            : _root;
        if (!Directory.Exists(baseDir)) return Array.Empty<string>();
        return Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(_root, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(k => k.StartsWith(p, StringComparison.Ordinal) && !k.EndsWith(".tmp", StringComparison.Ordinal))
            .OrderBy(k => k, StringComparer.Ordinal).ToList();
    }

    public void Delete(string key)
    {
        var full = FullPath(key);
        if (File.Exists(full)) File.Delete(full);
    }

    public long? FreeBytes
    {
        get
        {
            try { return new DriveInfo(Path.GetPathRoot(Path.GetFullPath(_root))!).AvailableFreeSpace; }
            catch { return null; }
        }
    }
}
