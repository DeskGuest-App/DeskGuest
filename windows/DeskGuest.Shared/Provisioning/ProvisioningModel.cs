using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Provisioning;

// =====================================================================
// RMM-29 — OS imaging / provisioning + profile migration. MODEL.
//
// An OS image is a versioned, hash-pinned DEFINITION composed from
// the programme's existing mechanisms — no parallel mechanisms:
//   * base image + driver pack are content references pinned by
//     SHA-256 (the RMM-14 content-addressing discipline);
//   * the application set is RMM-16 package ids ("id@version")
//     deployed by the package repository after imaging;
//   * configuration is RMM-07 policy document ids;
//   * post-provision steps are an RMM-20 runbook id.
// A provisioning RUN (ProvisioningRunner.cs) is an RMM-15 journal
// job authorised by an RMM-03 `provisioning` signed envelope.
//
// PROFILE MIGRATION IS ITS OWN CONTENT TYPE (the RMM-16 lane's
// recorded consumption contract, honoured exactly): profile data
// does NOT ride DeploymentPackages — packages bind licence values
// by hash under vault discipline, and user data is neither a
// component kind nor vault material. ProfilePackage below is the
// dedicated type: a declared, enumerated capture manifest (what is
// captured is enumerated, never "everything"), content sealed
// under the vault machinery (ISecretProtector), bound to its
// source device + user, and verified by manifest-hash comparison
// before a restore may complete.
//
// POLICY (TOTAL POLICY CONTROL): the feature toggle is
// `rmm.provisioning.enabled`, seeded OFF (ProvisioningService
// registers it into the RMM-07 registry with default OFF) —
// provisioning is destructive, so the model requires an EXPLICIT
// policy enable; the absence of a setting never enables it. The
// older `rmm.imaging.enabled` seed (RMM-07 registry, default ON)
// names the reporting surface, NOT the destructive run gate.
//
// The endpoint agent's role is orchestration + state machine +
// verification ONLY: PXE/network boot and the actual imaging are
// host machinery (WinPE / deployment share) behind IImagingExecutor.
// The production executor in this build is UnavailableImagingExecutor
// — honestly labelled; tests drive the fake. NOTHING in this lane
// images a real machine.
// =====================================================================

public static class ProvisioningPolicyKeys
{
    /// <summary>The destructive-run gate. Default OFF; an explicit
    /// policy setting of "true" is required to enable.</summary>
    public const string ProvisioningEnabled = "rmm.provisioning.enabled";
}

public static class ProvisioningHashing
{
    public static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text ?? ""));

    public static bool IsSha256Hex(string? s) =>
        s is { Length: 64 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

// ---- image definitions --------------------------------------------------

/// <summary>One versioned, hash-pinned OS image definition. Every
/// payload-bearing reference is pinned by SHA-256; the definition's
/// own ContentHash (over its canonical JSON) is what a provisioning
/// authorization binds, so swapping ANY component — base image,
/// driver pack, unattend, app set, policy set, runbook — after
/// authorization changes the hash and refuses at apply time.</summary>
public sealed record OsImageDefinition(
    string Id,
    string Version,
    string Name,
    bool Enabled,
    string BaseImageRef,
    string BaseImageHash,
    string DriverPackRef,
    string DriverPackHash,
    IReadOnlyList<string> ApplicationPackages,
    IReadOnlyList<string> PolicyDocumentIds,
    string? PostProvisionRunbookId,
    string? UnattendHash)
{
    public IReadOnlyList<string> ApplicationPackages { get; init; } = ApplicationPackages ?? Array.Empty<string>();
    public IReadOnlyList<string> PolicyDocumentIds { get; init; } = PolicyDocumentIds ?? Array.Empty<string>();

    public string ToCanonicalJson() => JsonSerializer.Serialize(new
    {
        id = Id, version = Version, name = Name, enabled = Enabled,
        baseImageRef = BaseImageRef, baseImageHash = (BaseImageHash ?? "").ToLowerInvariant(),
        driverPackRef = DriverPackRef, driverPackHash = (DriverPackHash ?? "").ToLowerInvariant(),
        applicationPackages = ApplicationPackages.OrderBy(p => p, StringComparer.Ordinal).ToArray(),
        policyDocumentIds = PolicyDocumentIds.OrderBy(p => p, StringComparer.Ordinal).ToArray(),
        postProvisionRunbookId = PostProvisionRunbookId,
        unattendHash = UnattendHash is null ? null : UnattendHash.ToLowerInvariant(),
    });

    public string ContentHash => ProvisioningHashing.Sha256Hex(ToCanonicalJson());

    public static OsImageDefinition? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            return new OsImageDefinition(
                r.GetProperty("id").GetString() ?? "",
                r.GetProperty("version").GetString() ?? "",
                r.GetProperty("name").GetString() ?? "",
                r.GetProperty("enabled").GetBoolean(),
                r.GetProperty("baseImageRef").GetString() ?? "",
                r.GetProperty("baseImageHash").GetString() ?? "",
                r.GetProperty("driverPackRef").GetString() ?? "",
                r.GetProperty("driverPackHash").GetString() ?? "",
                r.GetProperty("applicationPackages").EnumerateArray().Select(e => e.GetString() ?? "").ToList(),
                r.GetProperty("policyDocumentIds").EnumerateArray().Select(e => e.GetString() ?? "").ToList(),
                r.TryGetProperty("postProvisionRunbookId", out var rb) && rb.ValueKind != JsonValueKind.Null ? rb.GetString() : null,
                r.TryGetProperty("unattendHash", out var ua) && ua.ValueKind != JsonValueKind.Null ? ua.GetString() : null);
        }
        catch { return null; }
    }

    /// <summary>Null when admissible; otherwise the named refusal.
    /// Fail-closed on every ambiguity.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id)) return "image definition needs an id — refused";
        if (string.IsNullOrWhiteSpace(Version)) return $"image '{Id}' needs a version — refused";
        if (string.IsNullOrWhiteSpace(Name)) return $"image '{Id}' needs a name — refused";
        if (string.IsNullOrWhiteSpace(BaseImageRef)) return $"image '{Id}' names no base image reference — refused";
        if (!ProvisioningHashing.IsSha256Hex(BaseImageHash))
            return $"image '{Id}' base image hash is not a SHA-256 hex digest — refused (an unpinned base image is not an image definition)";
        if (string.IsNullOrWhiteSpace(DriverPackRef)) return $"image '{Id}' names no driver pack reference — refused";
        if (!ProvisioningHashing.IsSha256Hex(DriverPackHash))
            return $"image '{Id}' driver pack hash is not a SHA-256 hex digest — refused";
        if (UnattendHash is not null && !ProvisioningHashing.IsSha256Hex(UnattendHash))
            return $"image '{Id}' unattend hash is not a SHA-256 hex digest — refused";
        foreach (var p in ApplicationPackages)
        {
            var at = (p ?? "").IndexOf('@');
            if (at <= 0 || at == p.Length - 1)
                return $"image '{Id}' application package reference '{p}' is not in id@version form (RMM-16) — refused";
        }
        foreach (var d in PolicyDocumentIds)
            if (string.IsNullOrWhiteSpace(d))
                return $"image '{Id}' carries an empty policy document id (RMM-07) — refused";
        if (PostProvisionRunbookId is not null && string.IsNullOrWhiteSpace(PostProvisionRunbookId))
            return $"image '{Id}' carries an empty post-provision runbook id (RMM-20) — refused";
        return null;
    }
}

/// <summary>The image-definition store. Admission recomputes the
/// definition's validation; the same id+version with different
/// content is a conflict and refuses (a definition, once admitted,
/// never silently changes under a run that pinned its hash).
/// Revocation is a state, retained in the listing — a revoked image
/// refuses new authorizations and in-flight applies alike.</summary>
public sealed class ImageRepository
{
    private readonly Dictionary<string, OsImageDefinition> _images = new(StringComparer.Ordinal);
    private readonly HashSet<string> _revoked = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    private static string Key(string id, string version) =>
        (id ?? "").Trim().ToLowerInvariant() + "@" + (version ?? "").Trim();

    public string? Admit(OsImageDefinition image)
    {
        if (image is null) return "no image definition — refused";
        if (image.Validate() is { } v) return v;
        lock (_gate)
        {
            var key = Key(image.Id, image.Version);
            if (_images.TryGetValue(key, out var existing))
            {
                if (existing.ContentHash != image.ContentHash)
                    return $"image '{image.Id}' version '{image.Version}' is already admitted with different content (hash {existing.ContentHash}) — conflict refused; publish a new version instead";
                return null; // idempotent re-admission of identical content
            }
            _images[key] = image;
            return null;
        }
    }

    public OsImageDefinition? Get(string id, string version)
    {
        lock (_gate) return _images.TryGetValue(Key(id, version), out var img) ? img : null;
    }

    public bool IsRevoked(string id, string version)
    {
        lock (_gate) return _revoked.Contains(Key(id, version));
    }

    public bool Revoke(string id, string version)
    {
        lock (_gate)
        {
            if (!_images.ContainsKey(Key(id, version))) return false;
            _revoked.Add(Key(id, version));
            return true;
        }
    }

    public IReadOnlyList<OsImageDefinition> List()
    {
        lock (_gate) return _images.Values
            .OrderBy(i => i.Id, StringComparer.Ordinal).ThenBy(i => i.Version, StringComparer.Ordinal).ToList();
    }

    /// <summary>bd-shared-plat-2/F5: the revocation set persists —
    /// a restart must never un-revoke an image.</summary>
    public string ExportRevocationsJson()
    {
        lock (_gate) return System.Text.Json.JsonSerializer.Serialize(
            _revoked.OrderBy(r => r, StringComparer.Ordinal).ToArray());
    }

    public int ImportRevocationsJson(string json)
    {
        string[]? keys;
        try { keys = System.Text.Json.JsonSerializer.Deserialize<string[]>(json); }
        catch { return 0; }
        if (keys is null) return 0;
        var n = 0;
        lock (_gate)
            foreach (var k in keys)
                if (!string.IsNullOrWhiteSpace(k) && _revoked.Add(k)) n++;
        return n;
    }
}

// ---- profile migration (its own content type) ----------------------------

/// <summary>What a profile capture may contain — a CLOSED category
/// vocabulary. A capture declares its entries; there is no
/// "everything" category, by design.</summary>
public static class ProfileCategories
{
    public const string Documents = "documents";
    public const string Settings = "settings";
    public const string AppState = "app_state";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Documents, Settings, AppState };
}

/// <summary>One DECLARED capture entry: the enumeration of what will
/// be captured, agreed before capture runs. Capture that produces
/// anything outside this enumeration — or misses an entry — is not
/// a verified capture.</summary>
public sealed record ProfileManifestEntry(string Path, string Category);

/// <summary>One captured entry as sealed into a package: path,
/// category, size, and the SHA-256 of its content. The package
/// manifest hash covers every line, in path order.</summary>
public sealed record ProfileSealedEntry(string Path, string Category, long SizeBytes, string Sha256);

/// <summary>The declared capture manifest for one source device +
/// user. This enumeration IS the capture contract.</summary>
public sealed record ProfileCaptureManifest(
    string SourceDeviceId,
    string SourceUserId,
    IReadOnlyList<ProfileManifestEntry> Entries)
{
    public IReadOnlyList<ProfileManifestEntry> Entries { get; init; } = Entries ?? Array.Empty<ProfileManifestEntry>();

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(SourceDeviceId)) return "profile manifest names no source device — refused";
        if (string.IsNullOrWhiteSpace(SourceUserId)) return "profile manifest names no source user — refused";
        if (Entries.Count == 0) return "profile manifest enumerates nothing — refused (a capture of nothing is not a profile capture)";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in Entries)
        {
            if (string.IsNullOrWhiteSpace(e.Path)) return "profile manifest carries an empty path — refused";
            var p = e.Path.Replace('\\', '/');
            // F12 (D38 rmm29): traversal is a PATH-SEGMENT property —
            // a ".." segment refuses; a legitimate name that merely
            // contains the characters ("file..txt") does not.
            if (p.StartsWith('/') || p.Split('/').Any(seg => seg == "..") || (p.Length >= 2 && p[1] == ':'))
                return $"profile manifest path '{e.Path}' is rooted or traverses — refused (manifest paths are profile-relative)";
            if (!ProfileCategories.All.Contains(e.Category ?? ""))
                return $"profile manifest path '{e.Path}' names unknown category '{e.Category}' — refused";
            if (!seen.Add(e.Path)) return $"profile manifest enumerates '{e.Path}' twice — refused";
        }
        return null;
    }
}

/// <summary>A captured user profile: DeskGuest's dedicated profile content
/// type (NOT an RMM-16 package — see the file header). Bound to its
/// source device + user. Content is sealed under the vault machinery
/// (ISecretProtector): the record carries only the sealed blob, the
/// per-entry hashes, and the manifest hash. Verification decrypts
/// and recomputes — a manifest/content mismatch refuses restore.</summary>
public sealed record ProfilePackage(
    string Id,
    string SourceDeviceId,
    string SourceUserId,
    IReadOnlyList<ProfileSealedEntry> Entries,
    string ManifestHash,
    string SealedContentBase64,
    DateTimeOffset CapturedUtc)
{
    public IReadOnlyList<ProfileSealedEntry> Entries { get; init; } = Entries ?? Array.Empty<ProfileSealedEntry>();

    /// <summary>The manifest hash over the sealed entries + source
    /// binding — the value restore compares before completing.</summary>
    public static string ComputeManifestHash(string sourceDeviceId, string sourceUserId,
        IReadOnlyList<ProfileSealedEntry> entries) =>
        ProvisioningHashing.Sha256Hex(JsonSerializer.Serialize(new
        {
            sourceDeviceId, sourceUserId,
            entries = entries.OrderBy(e => e.Path, StringComparer.Ordinal)
                .Select(e => new { path = e.Path, category = e.Category, size = e.SizeBytes, sha256 = e.Sha256 }).ToArray(),
        }));
}

/// <summary>One item produced by a capture source: profile-relative
/// path + content bytes.</summary>
public sealed record ProfileCapturedItem(string Path, byte[] Content);

/// <summary>The agent-side profile capture contract. Implementations
/// read exactly the declared manifest's paths for the source user.
/// The production capture (USMT-class tooling on Windows) is host
/// machinery; tests drive the fake. NO implementation in this lane
/// reads a real user profile.</summary>
public interface IProfileCaptureSource
{
    IReadOnlyList<ProfileCapturedItem> Capture(ProfileCaptureManifest manifest);
}

/// <summary>Scripted capture double (house pattern). Contents are
/// keyed by exact manifest path; can omit or add paths to prove the
/// enumeration discipline, and can be scripted to throw.</summary>
public sealed class FakeProfileCaptureSource : IProfileCaptureSource
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);
    private Exception? _throw;
    public int CallCount { get; private set; }

    public FakeProfileCaptureSource Add(string path, string content)
    { _files[path] = Encoding.UTF8.GetBytes(content); return this; }

    public FakeProfileCaptureSource AddBytes(string path, byte[] content)
    { _files[path] = content; return this; }

    public FakeProfileCaptureSource ThenThrow(Exception ex) { _throw = ex; return this; }

    public IReadOnlyList<ProfileCapturedItem> Capture(ProfileCaptureManifest manifest)
    {
        CallCount++;
        if (_throw is not null) throw _throw;
        return _files.Select(kv => new ProfileCapturedItem(kv.Key, kv.Value.ToArray())).ToList();
    }
}

/// <summary>bd-shared-plat-2/F6: the restore WRITE seam — where
/// restored profile entries actually land on the target. Restore
/// without a target verifies only; a run that claims a completed
/// restore must go through a target and read the entries back.</summary>
public interface IProfileRestoreTarget
{
    /// <summary>Write one entry; returns the SHA-256 of what the
    /// target now holds for that path (read back), or null.</summary>
    string? WriteAndReadBack(string targetDeviceId, string targetUserId, string path, byte[] content);
}

/// <summary>Honest unavailable target: writes nothing, reads back
/// nothing — a restore stage wired with it FAILS by name.</summary>
public sealed class UnavailableProfileRestoreTarget : IProfileRestoreTarget
{
    public string? WriteAndReadBack(string targetDeviceId, string targetUserId, string path, byte[] content) => null;
}

/// <summary>In-memory restore double (house pattern): stores the
/// bytes and reads them back honestly.</summary>
public sealed class FakeProfileRestoreTarget : IProfileRestoreTarget
{
    public Dictionary<string, byte[]> Written { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? WriteAndReadBack(string targetDeviceId, string targetUserId, string path, byte[] content)
    {
        Written[$"{targetDeviceId}|{targetUserId}|{path}"] = content.ToArray();
        return ProvisioningHashing.Sha256Hex(content);
    }
}

/// <summary>An audited cross-user restore decision. A profile package
/// is bound to its source user; restoring it to a DIFFERENT user is
/// never silent — it requires a decision record naming the approver
/// (who must not be the requester) before the restore stage runs.</summary>
public sealed record CrossUserRestoreDecision(
    string Id, string SourceUserId, string TargetUserId,
    string RequestedBy, string ApprovedBy, DateTimeOffset DecidedUtc, string Reason,
    // F6 (D38 rmm29): a decision MAY be bound at registration time
    // to one run / device / captured package; when bound, the
    // runner enforces the binding at restore — an unbound decision
    // can no longer be assumed to cover a different run's restore
    // just because the user pair matches, and a bound one can
    // never be replayed onto another run, device or package.
    string? RunId = null, string? DeviceId = null, string? ProfilePackageId = null);

/// <summary>Capture → seal → verify → restore for profile packages.
/// Verification is total: unseal, recompute every entry's hash and
/// size, recompute the manifest hash — any mismatch refuses.</summary>
public sealed class ProfileMigrationEngine
{
    private readonly ISecretProtector _protector;

    public ProfileMigrationEngine(ISecretProtector protector) =>
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));

    /// <summary>Whether the vault machinery in force is real
    /// protection (DPAPI on Windows) or the dev pass-through —
    /// surfaced, never hidden (the RMM-16 vault honesty rule).</summary>
    public bool IsRealProtection => _protector.IsRealProtection;

    // F9 (D38 rmm29): the source binding is sealed INSIDE the
    // protected blob, not just covered by the unkeyed manifest
    // hash over record fields. Rebinding SourceDeviceId/SourceUserId
    // on the record and recomputing ManifestHash no longer verifies:
    // Verify compares the SEALED binding against the record's, and
    // rewriting the sealed binding requires the vault protector —
    // the same trust boundary that protects the content itself.
    private static string SerializeContent(IReadOnlyList<ProfileCapturedItem> items,
        string sourceDeviceId, string sourceUserId) =>
        JsonSerializer.Serialize(new
        {
            sourceDeviceId, sourceUserId,
            items = items.OrderBy(i => i.Path, StringComparer.Ordinal)
                .Select(i => new { path = i.Path, content = Convert.ToBase64String(i.Content) }).ToArray(),
        });

    private sealed record UnsealedContent(string SourceDeviceId, string SourceUserId,
        List<ProfileCapturedItem> Items);

    private static UnsealedContent? DeserializeContent(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var items = new List<ProfileCapturedItem>();
            foreach (var e in root.GetProperty("items").EnumerateArray())
                items.Add(new ProfileCapturedItem(
                    e.GetProperty("path").GetString() ?? "",
                    Convert.FromBase64String(e.GetProperty("content").GetString() ?? "")));
            return new UnsealedContent(
                root.GetProperty("sourceDeviceId").GetString() ?? "",
                root.GetProperty("sourceUserId").GetString() ?? "",
                items);
        }
        catch { return null; }
    }

    /// <summary>Build a sealed package from a capture. Refusals
    /// (null + reason): an invalid manifest; a capture whose item
    /// set differs from the declared enumeration in EITHER direction
    /// (missing entries mean the capture lied by omission; extra
    /// entries mean it captured what was never declared).</summary>
    public (ProfilePackage? Package, string Reason) CaptureAndSeal(
        ProfileCaptureManifest manifest, IProfileCaptureSource source, DateTimeOffset now)
    {
        if (manifest is null) return (null, "no profile manifest — capture refused");
        if (manifest.Validate() is { } mv) return (null, mv);
        if (source is null) return (null, "no profile capture source — capture refused");
        IReadOnlyList<ProfileCapturedItem> items;
        try { items = source.Capture(manifest); }
        catch (Exception ex) { return (null, $"profile capture source failed: {ex.Message}"); }
        items ??= Array.Empty<ProfileCapturedItem>();

        var declared = manifest.Entries.Select(e => e.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var got = items.Select(i => i.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missing = declared.Except(got, StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
            return (null, $"profile capture is missing declared entries ({string.Join(", ", missing)}) — an incomplete capture is not a verified capture; refused");
        var extra = got.Except(declared, StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.Ordinal).ToList();
        if (extra.Count > 0)
            return (null, $"profile capture produced undeclared entries ({string.Join(", ", extra)}) — capture may only contain the enumerated manifest; refused");
        if (items.GroupBy(i => i.Path, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            return (null, "profile capture produced a path twice — refused");

        var catByPath = manifest.Entries.ToDictionary(e => e.Path, e => e.Category, StringComparer.OrdinalIgnoreCase);
        var sealedEntries = items.Select(i => new ProfileSealedEntry(
            i.Path, catByPath[i.Path], i.Content.LongLength, ProvisioningHashing.Sha256Hex(i.Content)))
            .OrderBy(e => e.Path, StringComparer.Ordinal).ToList();
        var manifestHash = ProfilePackage.ComputeManifestHash(manifest.SourceDeviceId, manifest.SourceUserId, sealedEntries);
        var sealedBlob = _protector.Protect(Convert.ToBase64String(
            Encoding.UTF8.GetBytes(SerializeContent(items, manifest.SourceDeviceId, manifest.SourceUserId))));
        var pkg = new ProfilePackage(
            Guid.NewGuid().ToString("N"), manifest.SourceDeviceId, manifest.SourceUserId,
            sealedEntries, manifestHash, sealedBlob, now);
        // A package that does not verify the moment it is sealed is
        // not a package: self-check before returning it.
        var (ok, reason) = Verify(pkg);
        return ok ? (pkg, "profile captured and sealed; verification passed")
                  : (null, $"freshly sealed profile package failed verification: {reason}");
    }

    /// <summary>Verify a package end-to-end: the stored manifest
    /// hash must equal the recomputed manifest hash over the stored
    /// entries + binding, and every entry's content (from the
    /// unsealed blob) must recompute to its sealed hash and size.</summary>
    public (bool Ok, string Reason) Verify(ProfilePackage? package)
    {
        if (package is null) return (false, "no profile package — verification refused");
        var recomputed = ProfilePackage.ComputeManifestHash(package.SourceDeviceId, package.SourceUserId, package.Entries);
        if (!string.Equals(recomputed, (package.ManifestHash ?? "").ToLowerInvariant(), StringComparison.Ordinal))
            return (false, "profile manifest hash mismatch — the package's entries or source binding were altered after sealing; refused");
        UnsealedContent? unsealed;
        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(
                _protector.Unprotect(package.SealedContentBase64 ?? "")));
            unsealed = DeserializeContent(json);
        }
        catch { return (false, "profile package content cannot be unsealed — refused"); }
        if (unsealed is null) return (false, "profile package content does not parse — refused");
        // F9: the binding sealed inside the blob must be the
        // binding the record claims — a record-side rebind (even
        // with a recomputed manifest hash) refuses here.
        if (!string.Equals(unsealed.SourceDeviceId, package.SourceDeviceId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(unsealed.SourceUserId, package.SourceUserId, StringComparison.OrdinalIgnoreCase))
            return (false, "the package's sealed source binding does not match its record binding — the package was rebound after sealing; refused");
        var items = unsealed.Items;
        if (items.Count != package.Entries.Count)
            return (false, $"profile content holds {items.Count} items but the manifest seals {package.Entries.Count} entries — mismatch; refused");
        // A crafted blob holding one path twice must REFUSE, not
        // throw out of verification (recovery lane #2 fix).
        if (items.GroupBy(i => i.Path, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            return (false, "profile content holds a path more than once — manifest/content mismatch; refused");
        var byPath = items.ToDictionary(i => i.Path, StringComparer.OrdinalIgnoreCase);
        foreach (var e in package.Entries)
        {
            if (!byPath.TryGetValue(e.Path, out var item))
                return (false, $"profile content is missing sealed entry '{e.Path}' — manifest/content mismatch; refused");
            if (item.Content.LongLength != e.SizeBytes)
                return (false, $"profile entry '{e.Path}' size mismatch (sealed {e.SizeBytes}, content {item.Content.LongLength}) — refused");
            if (!string.Equals(ProvisioningHashing.Sha256Hex(item.Content), e.Sha256, StringComparison.Ordinal))
                return (false, $"profile entry '{e.Path}' content hash mismatch — the package was tampered with after sealing; refused");
        }
        return (true, "profile package verified (manifest hash + every entry hash recomputed)");
    }

    /// <summary>Restore a package onto a target. Refusals: an
    /// unverifiable package; a cross-user restore without an audited
    /// decision naming this source→target pair. On success returns
    /// the restored entries and the manifest hash the restore
    /// verified against — the run's restore stage completes only
    /// when the two agree.</summary>
    public (bool Ok, string Reason, IReadOnlyList<ProfileSealedEntry> Restored, string? VerifiedManifestHash) Restore(
        ProfilePackage? package, string targetDeviceId, string targetUserId,
        CrossUserRestoreDecision? crossUserDecision)
    {
        var none = Array.Empty<ProfileSealedEntry>();
        if (string.IsNullOrWhiteSpace(targetDeviceId)) return (false, "restore names no target device — refused", none, null);
        if (string.IsNullOrWhiteSpace(targetUserId)) return (false, "restore names no target user — refused", none, null);
        var (ok, reason) = Verify(package);
        if (!ok) return (false, reason, none, null);
        if (!string.Equals(package!.SourceUserId, targetUserId, StringComparison.OrdinalIgnoreCase))
        {
            if (crossUserDecision is null)
                return (false, $"profile is bound to user '{package.SourceUserId}' and the restore target user is '{targetUserId}' — a cross-user restore requires a separate audited decision; refused", none, null);
            if (!string.Equals(crossUserDecision.SourceUserId, package.SourceUserId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(crossUserDecision.TargetUserId, targetUserId, StringComparison.OrdinalIgnoreCase))
                return (false, "the cross-user decision presented does not name this source→target user pair — refused", none, null);
            if (string.IsNullOrWhiteSpace(crossUserDecision.ApprovedBy) ||
                string.Equals(crossUserDecision.ApprovedBy, crossUserDecision.RequestedBy, StringComparison.OrdinalIgnoreCase))
                return (false, "the cross-user decision has no approver distinct from its requester — refused (a self-approved cross-user restore is a silent one)", none, null);
        }
        return (true, $"profile verified for restore to device '{targetDeviceId}' for user '{targetUserId}' (manifest verified; no restore target was supplied, so nothing was written — see RestoreToTarget)",
            package.Entries, package.ManifestHash);
    }

    /// <summary>bd-shared-plat-2/F6: restore that WRITES. Every
    /// sealed entry is written through the target and read back;
    /// the stage succeeds only when every read-back hash equals
    /// the sealed entry hash. A target that writes nothing (the
    /// Unavailable double) fails every entry by name.</summary>
    public (bool Ok, string Reason, IReadOnlyList<ProfileSealedEntry> Restored, string? VerifiedManifestHash) RestoreToTarget(
        ProfilePackage? package, string targetDeviceId, string targetUserId,
        CrossUserRestoreDecision? crossUserDecision, IProfileRestoreTarget? target)
    {
        var none = Array.Empty<ProfileSealedEntry>();
        if (target is null)
            return (false, "no profile restore target is wired — restore writes nothing and refuses rather than claiming a restore (bd-shared-plat-2/F6)", none, null);
        var (ok, reason, _, _) = Restore(package, targetDeviceId, targetUserId, crossUserDecision);
        if (!ok) return (false, reason, none, null);
        UnsealedContent? unsealed;
        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(
                _protector.Unprotect(package!.SealedContentBase64 ?? "")));
            unsealed = DeserializeContent(json);
        }
        catch { return (false, "profile package content cannot be unsealed for restore — refused", none, null); }
        if (unsealed is null) return (false, "profile package content does not parse for restore — refused", none, null);
        var byPath = unsealed.Items.ToDictionary(i => i.Path, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in package.Entries)
        {
            if (!byPath.TryGetValue(entry.Path, out var item))
                return (false, $"restore content is missing sealed entry '{entry.Path}' — refused", none, null);
            string? readBack;
            try { readBack = target.WriteAndReadBack(targetDeviceId, targetUserId, entry.Path, item.Content); }
            catch (Exception ex) { return (false, $"restore target threw writing '{entry.Path}': {ex.Message}", none, null); }
            if (readBack is null || !string.Equals(readBack, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                return (false, $"restore read-back for '{entry.Path}' does not match the sealed hash (target reported {readBack ?? "nothing"}) — the entry did not verifiably land on the target", none, null);
        }
        return (true, $"profile restored to device '{targetDeviceId}' for user '{targetUserId}': {package.Entries.Count} entr(ies) written and read back against their sealed hashes",
            package.Entries, package.ManifestHash);
    }
}

// ---- bare-metal provisioning tokens ---------------------------------------

/// <summary>One-time provisioning tokens for bare-metal enrollment,
/// modelled on the RMM enrollment-code discipline (EnrollmentService):
/// minted hub-side WITH their binding (image id + content hash +
/// scope) fixed at mint time, single-use, expiring. The redeeming
/// machine can never choose or widen what the token provisions.
/// Only the token's hash is retained after mint in listings.</summary>
public sealed class ProvisioningTokenService
{
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(30);

    private sealed record PendingToken(string CodeHash, DateTimeOffset ExpiresUtc,
        string ImageId, string ImageVersion, string ImageContentHash, string ScopeId, string MintedBy);

    private readonly Dictionary<string, PendingToken> _pending = new(StringComparer.Ordinal);
    // F12 (D38 rmm29): consumed hashes carry their consumption
    // time and are pruned once they are far older than any token
    // TTL — a consumed hash only has to outlive the window in
    // which the token could be re-presented (after expiry the
    // pending entry is gone and replay refuses anyway).
    private readonly Dictionary<string, DateTimeOffset> _consumedHashes = new(StringComparer.Ordinal);
    private static readonly TimeSpan ConsumedRetention = TimeSpan.FromHours(2);
    private readonly object _gate = new();

    private void PruneConsumedLocked(DateTimeOffset now)
    {
        foreach (var dead in _consumedHashes.Where(kv => now - kv.Value > ConsumedRetention)
                     .Select(kv => kv.Key).ToList())
            _consumedHashes.Remove(dead);
    }

    public static string NormalizeCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return "";
        return new string(code.Where(c => c != '-' && !char.IsWhiteSpace(c))
            .Select(char.ToUpperInvariant).ToArray());
    }

    private static string GenerateCode()
    {
        const string alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        var chars = new char[10];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(chars);
    }

    public static string HashOf(string? code) => ProvisioningHashing.Sha256Hex(NormalizeCode(code));

    /// <summary>Mint a token bound to one image definition (id +
    /// version + content hash) and one scope. Returns the display
    /// code ONCE; the service retains only its hash.</summary>
    public string Mint(string imageId, string imageVersion, string imageContentHash,
        string scopeId, string mintedBy, DateTimeOffset now, TimeSpan? ttl = null)
    {
        if (string.IsNullOrWhiteSpace(imageId) || string.IsNullOrWhiteSpace(imageVersion))
            throw new ArgumentException("a provisioning token must bind an image id and version");
        if (!ProvisioningHashing.IsSha256Hex(imageContentHash))
            throw new ArgumentException("a provisioning token must bind the image definition's content hash");
        if (string.IsNullOrWhiteSpace(scopeId)) throw new ArgumentException("a provisioning token must bind a scope");
        var code = GenerateCode();
        lock (_gate)
        {
            foreach (var dead in _pending.Where(kv => now > kv.Value.ExpiresUtc).Select(kv => kv.Key).ToList())
                _pending.Remove(dead);
            _pending[HashOf(code)] = new PendingToken(HashOf(code),
                SafeExpiry(now, ttl ?? DefaultTtl), imageId.Trim(), imageVersion.Trim(),
                imageContentHash.ToLowerInvariant(), scopeId.Trim(), (mintedBy ?? "").Trim());
        }
        return code[..5] + "-" + code[5..];
    }

    private static DateTimeOffset SafeExpiry(DateTimeOffset now, TimeSpan ttl)
    {
        try { return now + ttl; }
        catch (ArgumentOutOfRangeException) { return ttl < TimeSpan.Zero ? DateTimeOffset.MinValue : DateTimeOffset.MaxValue; }
    }

    /// <summary>Redeem a token for the image it was bound to. Returns
    /// null (fail-closed) for unknown, expired, already-consumed, or
    /// binding-mismatched presentations. Consumption happens ONLY on
    /// a successful, binding-exact redemption — replay of a consumed
    /// token is refused by the consumed set even if the entry were
    /// somehow re-presented.</summary>
    public PendingTokenView? Redeem(string? code, string imageId, string imageVersion,
        string imageContentHash, DateTimeOffset now, string? expectedScope = null)
    {
        var normalized = NormalizeCode(code);
        if (normalized.Length != 10) return null;
        var hash = HashOf(normalized);
        lock (_gate)
        {
            PruneConsumedLocked(now);
            if (_consumedHashes.ContainsKey(hash)) return null; // replay
            if (!_pending.TryGetValue(hash, out var pending)) return null;
            if (now > pending.ExpiresUtc) { _pending.Remove(hash); return null; }
            if (!string.Equals(pending.ImageId, (imageId ?? "").Trim(), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(pending.ImageVersion, (imageVersion ?? "").Trim(), StringComparison.Ordinal) ||
                !string.Equals(pending.ImageContentHash, (imageContentHash ?? "").ToLowerInvariant(), StringComparison.Ordinal))
                return null; // binding mismatch: not consumed, caller may correct
            // F5 (D38 rmm29): the mint-time SCOPE is part of the
            // binding. A token minted for one customer scope never
            // provisions a device in another — scope mismatch is a
            // binding mismatch (refused, not consumed).
            if (!string.IsNullOrWhiteSpace(expectedScope) &&
                !string.Equals(pending.ScopeId, expectedScope.Trim(), StringComparison.OrdinalIgnoreCase))
                return null; // scope mismatch: not consumed, caller may correct
            _pending.Remove(hash);
            _consumedHashes[hash] = now;
            return new PendingTokenView(pending.ImageId, pending.ImageVersion, pending.ImageContentHash, pending.ScopeId, pending.MintedBy);
        }
    }

    public bool WasConsumed(string? code) { lock (_gate) return _consumedHashes.ContainsKey(HashOf(code)); }

    /// <summary>bd-shared-plat-2/F5: pending + consumed token state
    /// persists — a restart must never resurrect a consumed token
    /// (replay) or lose a pending token's binding.</summary>
    public string ExportJson()
    {
        lock (_gate) return DeskGuest.Shared.Hub.HubPersistence.Wrap("deskguest-provisioning-tokens-v1",
            System.Text.Json.JsonSerializer.Serialize(new
            {
                Pending = _pending.Values.ToArray(),
                Consumed = _consumedHashes.Select(kv => new { Hash = kv.Key, AtUtc = kv.Value }).ToArray(),
            }));
    }

    public int ImportJson(string json)
    {
        var payload = DeskGuest.Shared.Hub.HubPersistence.Unwrap(json, "deskguest-provisioning-tokens-v1");
        if (payload is null) return 0;
        var n = 0;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(payload);
            lock (_gate)
            {
                foreach (var el in doc.RootElement.GetProperty("Pending").EnumerateArray())
                {
                    var t = el.Deserialize<PendingToken>();
                    if (t is not null && !_pending.ContainsKey(t.CodeHash)) { _pending[t.CodeHash] = t; n++; }
                }
                foreach (var el in doc.RootElement.GetProperty("Consumed").EnumerateArray())
                {
                    var h = el.GetProperty("Hash").GetString();
                    if (!string.IsNullOrWhiteSpace(h) && !_consumedHashes.ContainsKey(h))
                    { _consumedHashes[h] = el.GetProperty("AtUtc").GetDateTimeOffset(); n++; }
                }
            }
        }
        catch { return 0; }
        return n;
    }
    public int PendingCount { get { lock (_gate) return _pending.Count; } }
}

/// <summary>What a successful token redemption proves: the image
/// binding and scope fixed at mint time.</summary>
public sealed record PendingTokenView(string ImageId, string ImageVersion, string ImageContentHash, string ScopeId, string MintedBy);

// ---- imaging executor seam (host machinery) --------------------------------

public sealed record ImagingApplyRequest(OsImageDefinition Image, string TargetDeviceId, string RunId);

/// <summary>F11 (D38 rmm29): the executor reports the hash of
/// EVERY pinned payload component it applied — base image, driver
/// pack, and the unattend file when the definition pins one — so
/// the runner can verify the whole pinned set, not just the base
/// image. A component the definition pins but the executor does
/// not report is unverified, and the runner refuses it.</summary>
public sealed record ImagingApplyResult(bool Ok, string? AppliedBaseImageHash, string Reason,
    string? AppliedDriverPackHash = null, string? AppliedUnattendHash = null);

/// <summary>The host imaging machinery seam: PXE/network boot into
/// WinPE and the actual image apply are performed by the deployment
/// share / WinPE environment, NOT by the endpoint agent. The agent
/// orchestrates, authorizes, and verifies. Implementations report
/// the base-image hash they actually applied; the runner compares
/// it against the authorized definition before believing it.</summary>
public interface IImagingExecutor
{
    ImagingApplyResult ApplyImage(ImagingApplyRequest request);
}

/// <summary>Honestly-labelled production state: the WinPE/deployment
/// share machinery is host wiring that does not exist in this build,
/// so the executor refuses by name rather than pretending to image.</summary>
public sealed class UnavailableImagingExecutor : IImagingExecutor
{
    public ImagingApplyResult ApplyImage(ImagingApplyRequest request) =>
        new(false, null, "host imaging machinery (WinPE / deployment share) is not wired in this build — apply refuses rather than claiming an image was written");
}

/// <summary>Scripted imaging double. Applies the definition's pinned
/// base-image hash by default; can be scripted to apply a DIFFERENT
/// hash (the substitution attack), to fail, or to throw.</summary>
public sealed class FakeImagingExecutor : IImagingExecutor
{
    private string? _applyHashOverride;
    private string? _driverHashOverride;
    private string? _unattendHashOverride;
    private string? _failReason;
    private Exception? _throw;
    public int CallCount { get; private set; }
    public ImagingApplyRequest? LastRequest { get; private set; }

    public FakeImagingExecutor ApplyHash(string hash) { _applyHashOverride = hash; return this; }
    public FakeImagingExecutor ApplyDriverHash(string hash) { _driverHashOverride = hash; return this; }
    public FakeImagingExecutor ApplyUnattendHash(string hash) { _unattendHashOverride = hash; return this; }
    public FakeImagingExecutor ThenFail(string reason) { _failReason = reason; return this; }
    public FakeImagingExecutor ThenThrow(Exception ex) { _throw = ex; return this; }

    public ImagingApplyResult ApplyImage(ImagingApplyRequest request)
    {
        CallCount++;
        LastRequest = request;
        if (_throw is not null) throw _throw;
        if (_failReason is not null) return new ImagingApplyResult(false, null, _failReason);
        return new ImagingApplyResult(true, _applyHashOverride ?? request.Image.BaseImageHash,
            "fake executor applied the image",
            _driverHashOverride ?? request.Image.DriverPackHash,
            _unattendHashOverride ?? request.Image.UnattendHash);
    }
}
