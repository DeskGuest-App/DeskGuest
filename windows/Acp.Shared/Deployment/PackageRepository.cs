using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Shared.Deployment;

// =====================================================================
// RMM-16 — Software deployment: package repository + content packs.
// MODEL LAYER: the deployable unit, its hash-bound manifest, the
// licence-key vault discipline, the hub-side repository, and the
// starter content packs.
//
// Doctrine carried from the register + the lane assignment:
//   * A deployable unit = files + scripts + licence keys + pre/post
//     steps + uninstall, as ONE versioned package. Install and
//     uninstall are RMM-08 AutomationDefinitions — a package's
//     execution IS the remediation engine executing a definition
//     (PackageDeployment.cs / SoftwareDeploymentService consume
//     RemediationRunner; nothing here forks an executor).
//   * The package MANIFEST binds every component by SHA-256: file
//     bytes, script bodies, step shapes, and licence-key VALUES
//     (bound by hash — the value itself never appears in the
//     package, its canonical JSON, a listing, or an audit entry).
//     A package whose components do not recompute to its manifest
//     refuses at repository ADMISSION and again at DEPLOY time
//     (PackageDeployment.cs re-verifies before anything runs).
//   * Licence keys are SECRETS under vault discipline: the only
//     store is PackageSecretVault (ISecretProtector-protected at
//     rest). The package carries a licence REFERENCE + the value's
//     hash. Reveal happens exactly once — endpoint-side, into the
//     step executor's context at execution time (the substituting
//     executor in PackageDeployment.cs). Listings are a separate
//     DTO type that structurally cannot carry a key value.
//   * Repository admission is whole-package: validation, manifest
//     recomputation, and vault-hash agreement must ALL pass, or
//     nothing is admitted and the prior state stands. Same
//     id+version with different content refuses (conflict); a
//     revoked version refuses at deploy even though it remains in
//     the repository as history.
//   * Content packs are data with the same discipline: a versioned,
//     signed bundle of packages (they travel inside an RMM-03
//     policy_delivery envelope, like the RMM-08 library), revision-
//     monotonic per pack id, hash-bound per package. Starter packs
//     ship as local content; site-specific packs ship DISABLED with
//     placeholder site facts, never guessed (the RMM-01/08 pattern).
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-16. The global toggle
/// is the registry-seeded `rmm.software_deployment.enabled`
/// (RMM-07); per-package keys are computed from the package id.</summary>
public static class DeploymentPolicyKeys
{
    public const string DeploymentEnabled = "rmm.software_deployment.enabled";

    /// <summary>Per-package enable setting: "false" disables this
    /// one package for the device even while deployment is on.</summary>
    public static string PackageEnabled(string packageId) =>
        $"rmm.software_deployment.{NormalizeId(packageId)}.enabled";

    public static string NormalizeId(string? id) => (id ?? "").Trim().ToLowerInvariant();
}

/// <summary>The closed component-kind vocabulary. A package naming
/// a kind outside this set refuses at admission.</summary>
public static class PackageComponentKinds
{
    public const string File = "file";               // content-addressed bytes (RMM-14 manifest hash)
    public const string Script = "script";           // a run_script step body, hash-bound
    public const string LicenceKey = "licence_key";  // a vault reference, bound by value hash
    public const string Step = "step";               // a non-script remediation step shape

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { File, Script, LicenceKey, Step };
}

/// <summary>Named bounds for package admission. Every bound refuses
/// by name — none is a hidden constant.</summary>
public static class PackageLimits
{
    public const int MaxPackagesPerRepository = 512;
    public const int MaxFileComponents = 64;
    public const int MaxLicenceKeys = 16;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    public const int MaxVersionLength = 64;
    public const int MaxTargetPathLength = 512;
    public const int MaxPackagesPerPack = 64;
}

/// <summary>One file component: bytes identified by their RMM-14
/// content hash (the same hash the distribution layer fetches by).
/// The bytes themselves live in the PeerContentStore / hub content
/// store, never inside the package JSON.</summary>
public sealed record PackageFileComponent(string Name, string ContentHash, long SizeBytes, string TargetPath);

/// <summary>One licence-key component: a vault REFERENCE plus the
/// SHA-256 of the key value. The value is never in this record, so
/// it is never in the package's canonical JSON, its hash inputs
/// beyond the value hash, a listing, or an audit line.</summary>
public sealed record PackageLicenceComponent(string Ref, string ValueHash)
{
    /// <summary>Display fingerprint: the first 12 hex chars of the
    /// VALUE HASH — identifies which key a package binds without
    /// revealing any part of the key itself.</summary>
    public string Fingerprint => (ValueHash ?? "").Length >= 12 ? ValueHash[..12] : ValueHash ?? "";
}

/// <summary>One manifest binding: a component's kind, name, and the
/// SHA-256 its content must recompute to. The manifest is the
/// package's table of contents, and admission/deploy recompute
/// every line of it.</summary>
public sealed record ComponentBinding(string Kind, string Name, string Sha256);

/// <summary>How a component/steps hash is computed — one place, so
/// admission, deploy-time verification, and tests all recompute the
/// same bytes.</summary>
public static class PackageHashing
{
    public static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text ?? ""));

    public static string StepBindingHash(RemediationStep s) => Sha256Hex(string.Join("|",
        s.Id, s.Kind, s.Target ?? "", s.Argument ?? "", s.ScriptBody ?? "", s.When,
        s.GuardArgument ?? "", s.OnFailure, s.NextOnSuccess ?? "", s.NextOnFailure ?? "",
        s.MaxExecutions, s.Idempotent));

    /// <summary>The placeholder a step's Target/Argument/ScriptBody
    /// uses to consume a licence key at execution time:
    /// {licence:&lt;ref&gt;}. The template form is what is signed
    /// and hash-bound; substitution happens only inside the
    /// endpoint's step executor at run time.</summary>
    public static string LicencePlaceholder(string licenceRef) => "{licence:" + licenceRef + "}";
}

/// <summary>One versioned deployable package. Install and uninstall
/// are RMM-08 definitions: their steps ARE the pre/install/post and
/// uninstall step sequences (step order is the phase order — pre
/// steps first, then the install body, then post steps, authored
/// as one ordered list, exactly as an AutomationDefinition runs).
/// Enabled=false is the template state: admitted, listed, never
/// deployable until a signed revision enables it.</summary>
public sealed record DeploymentPackage(
    string Id,
    string Version,
    string Name,
    string Description,
    bool Enabled,
    string? InstalledSoftwareName,
    IReadOnlyList<PackageFileComponent> Files,
    IReadOnlyList<PackageLicenceComponent> LicenceKeys,
    AutomationDefinition Install,
    AutomationDefinition Uninstall)
{
    public IReadOnlyList<PackageFileComponent> Files { get; init; } = Files ?? Array.Empty<PackageFileComponent>();
    public IReadOnlyList<PackageLicenceComponent> LicenceKeys { get; init; } = LicenceKeys ?? Array.Empty<PackageLicenceComponent>();

    /// <summary>D38-F1: the manifest AS CARRIED in the canonical JSON
    /// this package was parsed from (null for code-constructed
    /// packages). Admission and deploy-time verification recompute
    /// the manifest and compare against THIS — never against a
    /// manifest recomputed from the same possibly-tampered
    /// components, which could never disagree with itself. The
    /// repository stamps it at admission (from the recomputed
    /// manifest when the package carried none) so every admitted
    /// package is anchored to what was admitted. Not part of the
    /// canonical JSON (the JSON's manifest field IS this value).</summary>
    public IReadOnlyList<ComponentBinding>? CarriedManifest { get; init; }

    /// <summary>The manifest: every component bound by hash, in a
    /// deterministic order (files by name, licences by ref, install
    /// steps then uninstall steps in authored order — step order is
    /// semantics, so it is NOT sorted).</summary>
    public IReadOnlyList<ComponentBinding> Manifest()
    {
        var bindings = new List<ComponentBinding>();
        foreach (var f in Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            bindings.Add(new ComponentBinding(PackageComponentKinds.File, f.Name, (f.ContentHash ?? "").ToLowerInvariant()));
        foreach (var l in LicenceKeys.OrderBy(l => l.Ref, StringComparer.Ordinal))
            bindings.Add(new ComponentBinding(PackageComponentKinds.LicenceKey, l.Ref, (l.ValueHash ?? "").ToLowerInvariant()));
        foreach (var s in Install.Steps)
            bindings.Add(new ComponentBinding(
                s.Kind == RemediationStepKinds.RunScript ? PackageComponentKinds.Script : PackageComponentKinds.Step,
                "install:" + s.Id, PackageHashing.StepBindingHash(s)));
        foreach (var s in Uninstall.Steps)
            bindings.Add(new ComponentBinding(
                s.Kind == RemediationStepKinds.RunScript ? PackageComponentKinds.Script : PackageComponentKinds.Step,
                "uninstall:" + s.Id, PackageHashing.StepBindingHash(s)));
        return bindings;
    }

    /// <summary>Deterministic canonical JSON — the exact bytes an
    /// RMM-03 envelope carries for repository/content-pack delivery.
    /// Contains NO licence values (refs + value hashes only) and no
    /// file bytes (content hashes only).</summary>
    public string ToCanonicalJson()
    {
        object Def(AutomationDefinition d) => new
        {
            id = d.Id, name = d.Name, description = d.Description, tier = d.ApprovalTier,
            cooldownSeconds = d.Cooldown.TotalSeconds, maxRunsPerWindow = d.MaxRunsPerWindow,
            windowSeconds = d.Window.TotalSeconds, enabled = d.Enabled,
            steps = d.Steps.Select(s => new
            {
                id = s.Id, kind = s.Kind, target = s.Target, argument = s.Argument,
                scriptBody = s.ScriptBody, when = s.When, guardArgument = s.GuardArgument,
                onFailure = s.OnFailure, nextOnSuccess = s.NextOnSuccess,
                nextOnFailure = s.NextOnFailure, maxExecutions = s.MaxExecutions,
                idempotent = s.Idempotent,
            }).ToList(),
        };
        return JsonSerializer.Serialize(new
        {
            id = Id, version = Version, name = Name, description = Description, enabled = Enabled,
            installedSoftwareName = InstalledSoftwareName,
            files = Files.OrderBy(f => f.Name, StringComparer.Ordinal)
                .Select(f => new { name = f.Name, contentHash = f.ContentHash, sizeBytes = f.SizeBytes, targetPath = f.TargetPath }).ToList(),
            licenceKeys = LicenceKeys.OrderBy(l => l.Ref, StringComparer.Ordinal)
                .Select(l => new { @ref = l.Ref, valueHash = l.ValueHash }).ToList(),
            install = Def(Install), uninstall = Def(Uninstall),
            manifest = Manifest().Select(b => new { kind = b.Kind, name = b.Name, sha256 = b.Sha256 }).ToList(),
        });
    }

    /// <summary>SHA-256 of the canonical JSON — the content identity
    /// deployments bind in their signed envelope and audit trail.</summary>
    public string ContentHash => PackageHashing.Sha256Hex(ToCanonicalJson());

    public static DeploymentPackage? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var files = new List<PackageFileComponent>();
            foreach (var f in root.GetProperty("files").EnumerateArray())
                files.Add(new PackageFileComponent(
                    f.GetProperty("name").GetString() ?? "",
                    f.GetProperty("contentHash").GetString() ?? "",
                    f.GetProperty("sizeBytes").GetInt64(),
                    f.GetProperty("targetPath").GetString() ?? ""));
            var licences = new List<PackageLicenceComponent>();
            foreach (var l in root.GetProperty("licenceKeys").EnumerateArray())
                licences.Add(new PackageLicenceComponent(
                    l.GetProperty("ref").GetString() ?? "",
                    l.GetProperty("valueHash").GetString() ?? ""));
            // D38-F1: read the EMBEDDED manifest — the binding the
            // signer actually signed over. Ignoring it (the old
            // behaviour) made the signed-path manifest check compare
            // the package against itself.
            List<ComponentBinding>? carried = null;
            if (root.TryGetProperty("manifest", out var manifestEl) &&
                manifestEl.ValueKind == JsonValueKind.Array)
            {
                carried = new List<ComponentBinding>();
                foreach (var b in manifestEl.EnumerateArray())
                    carried.Add(new ComponentBinding(
                        b.GetProperty("kind").GetString() ?? "",
                        b.GetProperty("name").GetString() ?? "",
                        b.GetProperty("sha256").GetString() ?? ""));
            }
            return new DeploymentPackage(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("version").GetString() ?? "",
                root.GetProperty("name").GetString() ?? "",
                OptString(root, "description") ?? "",
                root.GetProperty("enabled").GetBoolean(),
                OptString(root, "installedSoftwareName"),
                files, licences,
                ParseDef(root.GetProperty("install")), ParseDef(root.GetProperty("uninstall")))
            { CarriedManifest = carried };
        }
        catch { return null; }
    }

    private static AutomationDefinition ParseDef(JsonElement el)
    {
        var steps = new List<RemediationStep>();
        foreach (var s in el.GetProperty("steps").EnumerateArray())
            steps.Add(new RemediationStep(
                s.GetProperty("id").GetString() ?? "",
                s.GetProperty("kind").GetString() ?? "",
                OptString(s, "target"), OptString(s, "argument"), OptString(s, "scriptBody"),
                OptString(s, "when") ?? StepGuards.Always, OptString(s, "guardArgument"),
                OptString(s, "onFailure") ?? StepFailureModes.Stop,
                OptString(s, "nextOnSuccess"), OptString(s, "nextOnFailure"),
                s.GetProperty("maxExecutions").GetInt32(),
                s.GetProperty("idempotent").GetBoolean()));
        return new AutomationDefinition(
            el.GetProperty("id").GetString() ?? "",
            el.GetProperty("name").GetString() ?? "",
            OptString(el, "description") ?? "",
            el.GetProperty("tier").GetString() ?? "",
            TimeSpan.FromSeconds(el.GetProperty("cooldownSeconds").GetDouble()),
            el.GetProperty("maxRunsPerWindow").GetInt32(),
            TimeSpan.FromSeconds(el.GetProperty("windowSeconds").GetDouble()),
            el.GetProperty("enabled").GetBoolean(), steps);
    }

    private static string? OptString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Admission validation. Null when admissible;
    /// otherwise the refusal naming the first defect. Manifest
    /// agreement is checked by the repository (it owns the expected
    /// manifest a delivery carried); this checks the package's own
    /// shape, including that its embedded definitions pass RMM-08
    /// admission as a synthetic library.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > PackageLimits.MaxIdLength)
            return "package needs an id within bounds — refused";
        if (string.IsNullOrWhiteSpace(Version) || Version.Length > PackageLimits.MaxVersionLength)
            return $"package '{Id}': version empty or over bounds — refused";
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > PackageLimits.MaxNameLength)
            return $"package '{Id}': name empty or over bounds — refused";
        if (Files.Count > PackageLimits.MaxFileComponents)
            return $"package '{Id}': {Files.Count} file components over the cap {PackageLimits.MaxFileComponents} — refused";
        if (LicenceKeys.Count > PackageLimits.MaxLicenceKeys)
            return $"package '{Id}': {LicenceKeys.Count} licence keys over the cap {PackageLimits.MaxLicenceKeys} — refused";
        var fileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Files)
        {
            if (string.IsNullOrWhiteSpace(f.Name) || !fileNames.Add(f.Name))
                return $"package '{Id}': a file component name is empty or duplicated — refused";
            if (!IsSha256Hex(f.ContentHash))
                return $"package '{Id}' file '{f.Name}': content hash is not a SHA-256 hex digest — refused (files are bound by hash or not at all)";
            if (f.SizeBytes < 0)
                return $"package '{Id}' file '{f.Name}': negative size — refused";
            if (string.IsNullOrWhiteSpace(f.TargetPath) || f.TargetPath.Length > PackageLimits.MaxTargetPathLength)
                return $"package '{Id}' file '{f.Name}': target path empty or over bounds — refused";
        }
        var refs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in LicenceKeys)
        {
            if (string.IsNullOrWhiteSpace(l.Ref) || !refs.Add(l.Ref))
                return $"package '{Id}': a licence ref is empty or duplicated — refused";
            if (!IsSha256Hex(l.ValueHash))
                return $"package '{Id}' licence '{l.Ref}': value hash is not a SHA-256 hex digest — refused (a licence is bound by the hash of its value, never by the value)";
        }
        if (Install is null || Uninstall is null)
            return $"package '{Id}': install and uninstall definitions are both required — refused (uninstall is a first-class path, not an afterthought)";
        // Both definitions must pass RMM-08's own admission: the
        // package consumes the engine's vocabulary and bounds as-is.
        var probe = new AutomationLibrary($"pkg-probe:{Id}", 1, new[] { Install, Uninstall });
        if (probe.Validate() is { } defRefusal)
            return $"package '{Id}': {defRefusal}";
        // Every licence placeholder a step uses must name a licence
        // this package actually binds — a step reaching for a key
        // the manifest does not bind is exactly the smuggling shape.
        foreach (var step in Install.Steps.Concat(Uninstall.Steps))
        {
            foreach (var field in new[] { step.Target, step.Argument, step.ScriptBody })
            {
                if (field is null) continue;
                var idx = 0;
                // D38-F12a: the scan is case-INSENSITIVE, matching the
                // (case-insensitive) substitution at execution time —
                // a placeholder in any casing must name a bound ref.
                while ((idx = field.IndexOf("{licence:", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    var end = field.IndexOf('}', idx);
                    if (end < 0)
                        return $"package '{Id}' step '{step.Id}': unterminated licence placeholder — refused";
                    var referenced = field.Substring(idx + "{licence:".Length, end - idx - "{licence:".Length);
                    if (!refs.Contains(referenced))
                        return $"package '{Id}' step '{step.Id}': uses licence placeholder for '{referenced}', which this package does not bind — refused";
                    idx = end + 1;
                }
            }
        }
        return null;
    }

    /// <summary>Verify an EXPECTED manifest (the one a signed
    /// delivery carried) against this package's recomputed manifest.
    /// Null on agreement; otherwise the refusal naming the first
    /// mismatched component. This is the admission-time AND
    /// deploy-time component-mismatch gate.</summary>
    public string? VerifyManifest(IReadOnlyList<ComponentBinding> expected)
    {
        var actual = Manifest();
        if (expected is null || expected.Count != actual.Count)
            return $"package '{Id}' v{Version}: manifest component count mismatch (carried {(expected?.Count ?? -1)}, recomputed {actual.Count}) — refused: a component was added or removed after the manifest was bound";
        for (var i = 0; i < actual.Count; i++)
        {
            var e = expected[i]; var a = actual[i];
            if (e.Kind != a.Kind || e.Name != a.Name ||
                !string.Equals(e.Sha256, a.Sha256, StringComparison.OrdinalIgnoreCase))
                return $"package '{Id}' v{Version}: component '{a.Name}' ({a.Kind}) does not match its manifest binding — refused: the component changed after signing";
        }
        return null;
    }

    public static bool IsSha256Hex(string? s) =>
        s is { Length: 64 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
}

/// <summary>The licence-key vault. Values exist ONLY here, held as
/// ISecretProtector-protected text (DPAPI in production; the dev
/// pass-through in tests, named as such by the protector itself).
/// The vault's public surface never returns a value except through
/// Reveal — the execution path — and Reveal is the one operation
/// the deployment runner calls, endpoint-side, per execution.</summary>
public sealed class PackageSecretVault
{
    private sealed record Entry(string ProtectedValue, string ValueHash);
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISecretProtector _protector;
    private readonly object _gate = new();

    public PackageSecretVault(ISecretProtector protector) =>
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));

    /// <summary>Whether at-rest protection is real (DPAPI on
    /// Windows) or the named dev pass-through — surfaced honestly,
    /// never silently claimed.</summary>
    public bool IsRealProtection => _protector.IsRealProtection;
    public string ProtectorName => _protector.Name;

    /// <summary>Store a key value under a ref. Returns the value
    /// hash a package binds in its manifest.</summary>
    public string Store(string licenceRef, string value)
    {
        if (string.IsNullOrWhiteSpace(licenceRef) || string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("a licence entry needs a ref and a value");
        var hash = PackageHashing.Sha256Hex(value);
        lock (_gate) _entries[licenceRef] = new Entry(_protector.Protect(value), hash);
        return hash;
    }

    /// <summary>The stored value hash for a ref (null when the ref
    /// is unknown) — the admission/deploy agreement check.</summary>
    public string? HashOf(string licenceRef)
    {
        lock (_gate) return licenceRef is not null && _entries.TryGetValue(licenceRef, out var e) ? e.ValueHash : null;
    }

    public bool Has(string licenceRef) => HashOf(licenceRef) is not null;

    /// <summary>THE reveal: the ONLY path a value leaves the vault.
    /// Called by the deployment runner, endpoint-side, to build the
    /// execution context for one run. Callers must never log,
    /// persist, or audit the returned value.</summary>
    public string? Reveal(string licenceRef)
    {
        lock (_gate)
            return licenceRef is not null && _entries.TryGetValue(licenceRef, out var e)
                ? _protector.Unprotect(e.ProtectedValue) : null;
    }

    /// <summary>Vault refs held — refs are not secrets; values are.</summary>
    public IReadOnlyList<string> Refs
    {
        get { lock (_gate) return _entries.Keys.OrderBy(r => r, StringComparer.Ordinal).ToList(); }
    }
}

/// <summary>The repository LISTING DTO. A separate type from the
/// package on purpose: it has no licence-value field, no file-bytes
/// field, and no step-body field, so a listing can never leak a
/// secret by construction — the destruction pass greps listings
/// for key values and finds only refs + hash fingerprints.</summary>
public sealed record PackageListing(
    string Id, string Version, string Name, bool Enabled, bool Revoked,
    string ContentHash, int FileCount, IReadOnlyList<string> LicenceRefs,
    IReadOnlyList<string> LicenceFingerprints, int InstallSteps, int UninstallSteps);

/// <summary>The hub-side package repository. Admission is
/// whole-package (shape + manifest recomputation + vault agreement);
/// the admitted package is frozen by defensive copy. Revocation is
/// a deploy-time refusal that keeps history visible.</summary>
public sealed class PackageRepository
{
    private readonly Dictionary<string, DeploymentPackage> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _revoked = new(StringComparer.OrdinalIgnoreCase);
    private readonly PackageSecretVault _vault;
    private readonly object _gate = new();

    public PackageRepository(PackageSecretVault vault) =>
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));

    private static string Key(string id, string version) => $"{id}@{version}";

    public int Count { get { lock (_gate) return _byKey.Count; } }

    /// <summary>D38-F3: a deep snapshot of a package — NEW list
    /// instances for files, licences and both definitions' steps.
    /// Admission snapshots FIRST and runs every check against the
    /// snapshot (the old code validated the caller's live lists
    /// outside the lock, then copied them later — a mutation between
    /// check and copy was admitted unverified), and every read path
    /// (Get/Latest/All) hands out a fresh snapshot, so the stored
    /// package can never be mutated through a returned reference by
    /// casting its IReadOnlyList fields back to List&lt;T&gt;.</summary>
    private static DeploymentPackage Snapshot(DeploymentPackage p) => p with
    {
        Files = p.Files.ToList(),
        LicenceKeys = p.LicenceKeys.ToList(),
        Install = p.Install is null ? null! : p.Install with { Steps = p.Install.Steps.ToList() },
        Uninstall = p.Uninstall is null ? null! : p.Uninstall with { Steps = p.Uninstall.Steps.ToList() },
        CarriedManifest = p.CarriedManifest?.ToList(),
    };

    /// <summary>The vault-agreement gate, run against a snapshot.
    /// Null on agreement; otherwise the refusal.</summary>
    private string? CheckVaultAgreement(DeploymentPackage snap)
    {
        // Vault agreement: every bound licence must exist in the
        // vault with EXACTLY the bound value hash — a package that
        // names a key the vault does not hold (or holds differently)
        // would deploy a key that is not the key that was signed for.
        foreach (var lic in snap.LicenceKeys)
        {
            var vaultHash = _vault.HashOf(lic.Ref);
            if (vaultHash is null)
                return $"package '{snap.Id}' v{snap.Version}: licence '{lic.Ref}' is not in the vault — refused (a package never carries its keys; the vault does)";
            if (!string.Equals(vaultHash, lic.ValueHash, StringComparison.OrdinalIgnoreCase))
                return $"package '{snap.Id}' v{snap.Version}: licence '{lic.Ref}' value hash does not match the vault entry — refused (the vault's key is not the key this package was signed for)";
        }
        return null;
    }

    /// <summary>Snapshot + shape + manifest + vault checks shared by
    /// Admit and AdmitAll. On success <paramref name="snap"/> is the
    /// frozen snapshot to store (its CarriedManifest stamped from
    /// the recomputed manifest when the package carried none, so the
    /// admitted binding anchors deploy-time verification — D38-F2).</summary>
    private string? PrepareSnapshot(DeploymentPackage package,
        IReadOnlyList<ComponentBinding>? expectedManifest, out DeploymentPackage snap)
    {
        snap = Snapshot(package);
        if (snap.Validate() is { } invalid) return invalid;
        // D38-F1: the expected manifest defaults to the manifest the
        // package CARRIED in its signed JSON — an independent value
        // the signer signed over — never silently to a manifest
        // recomputed from the components under test.
        var expected = expectedManifest ?? snap.CarriedManifest;
        if (expected is not null && snap.VerifyManifest(expected) is { } mismatch)
            return mismatch;
        if (CheckVaultAgreement(snap) is { } vaultRefusal) return vaultRefusal;
        snap = snap with { CarriedManifest = (expected ?? snap.Manifest()).ToList() };
        return null;
    }

    /// <summary>Admit a package. <paramref name="expectedManifest"/>
    /// is the manifest the signed delivery carried; when null, the
    /// package's own CARRIED manifest (parsed from its canonical
    /// JSON) is the binding — for a code-constructed local package
    /// with no carried manifest, the package's recomputed manifest
    /// is the binding. Refusals change nothing.</summary>
    public (bool Admitted, string Reason) Admit(DeploymentPackage package,
        IReadOnlyList<ComponentBinding>? expectedManifest = null)
    {
        if (package is null) return (false, "no package — refused");
        if (PrepareSnapshot(package, expectedManifest, out var snap) is { } refusal)
            return (false, refusal);
        lock (_gate)
        {
            if (_byKey.Count >= PackageLimits.MaxPackagesPerRepository &&
                !_byKey.ContainsKey(Key(snap.Id, snap.Version)))
                return (false, $"repository is at its cap of {PackageLimits.MaxPackagesPerRepository} packages — refused");
            if (_byKey.TryGetValue(Key(snap.Id, snap.Version), out var existing))
            {
                if (existing.ContentHash != snap.ContentHash)
                    return (false, $"package '{snap.Id}' v{snap.Version} conflicts with the admitted package of the same id+version — refused (same version, different content is a supply-chain attack shape)");
                return (true, $"package '{snap.Id}' v{snap.Version} already admitted (idempotent)");
            }
            // The snapshot IS the defensive copy: its lists were
            // created here, the caller holds no reference to them.
            _byKey[Key(snap.Id, snap.Version)] = snap;
            Changed?.Invoke();
            return (true, $"package '{snap.Id}' v{snap.Version} admitted (hash {snap.ContentHash[..12]}…)");
        }
    }

    /// <summary>D38-F8: admit a batch ATOMICALLY — every package is
    /// snapshotted and checked (shape, carried manifest, vault,
    /// conflicts, AND the repository cap accounting for the whole
    /// batch) before ANY is stored, all under one lock. The old
    /// per-package loop could refuse partway (e.g. at the cap) and
    /// leave a "refused" pack half-admitted. Refusals change
    /// nothing.</summary>
    public (bool Admitted, string Reason) AdmitAll(IReadOnlyList<DeploymentPackage> packages)
    {
        if (packages is null || packages.Count == 0) return (false, "no packages — refused");
        var snaps = new List<DeploymentPackage>(packages.Count);
        var batchKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in packages)
        {
            if (package is null) return (false, "no package — refused");
            if (PrepareSnapshot(package, null, out var snap) is { } refusal)
                return (false, refusal);
            if (!batchKeys.Add(Key(snap.Id, snap.Version)))
                return (false, $"package '{snap.Id}' v{snap.Version} appears twice in the batch — refused");
            snaps.Add(snap);
        }
        lock (_gate)
        {
            var fresh = 0;
            foreach (var snap in snaps)
            {
                if (_byKey.TryGetValue(Key(snap.Id, snap.Version), out var existing))
                {
                    if (existing.ContentHash != snap.ContentHash)
                        return (false, $"package '{snap.Id}' v{snap.Version} conflicts with the admitted package of the same id+version — refused (same version, different content is a supply-chain attack shape)");
                }
                else fresh++;
            }
            if (_byKey.Count + fresh > PackageLimits.MaxPackagesPerRepository)
                return (false, $"admitting this batch would exceed the repository cap of {PackageLimits.MaxPackagesPerRepository} packages — refused whole, nothing admitted");
            var added = 0;
            foreach (var snap in snaps)
                if (!_byKey.ContainsKey(Key(snap.Id, snap.Version)))
                { _byKey[Key(snap.Id, snap.Version)] = snap; added++; }
            if (added > 0) Changed?.Invoke();
            return (true, $"{snaps.Count} package(s) admitted atomically ({added} new)");
        }
    }

    /// <summary>D38-F2: the content hash recorded at admission for
    /// this id+version, recomputed from the repository's own stored
    /// snapshot (which no caller can reach or mutate — see
    /// Snapshot). The deploy path compares the package it is about
    /// to sign/run against this anchor; null when not admitted.</summary>
    public string? AdmittedContentHash(string packageId, string version)
    {
        lock (_gate) return _byKey.TryGetValue(Key(packageId ?? "", version ?? ""), out var p)
            ? p.ContentHash : null;
    }

    public DeploymentPackage? Get(string packageId, string version)
    {
        // D38-F3: a fresh snapshot per call — never the stored object.
        lock (_gate) return _byKey.TryGetValue(Key(packageId ?? "", version ?? ""), out var p)
            ? Snapshot(p) : null;
    }

    /// <summary>The highest admitted version of a package (version
    /// order is RMM-04 SoftwareVersion semantics, never raw text).</summary>
    public DeploymentPackage? Latest(string packageId)
    {
        lock (_gate)
        {
            DeploymentPackage? best = null;
            foreach (var p in _byKey.Values.Where(p =>
                string.Equals(p.Id, packageId, StringComparison.OrdinalIgnoreCase)))
                if (best is null || SoftwareVersion.Compare(p.Version, best.Version) > 0) best = p;
            return best is null ? null : Snapshot(best);
        }
    }

    public IReadOnlyList<DeploymentPackage> All
    {
        get { lock (_gate) return _byKey.Values
            .OrderBy(p => p.Id, StringComparer.Ordinal).ThenBy(p => p.Version, StringComparer.Ordinal)
            .Select(Snapshot).ToList(); }
    }

    public void Revoke(string packageId, string version)
    {
        lock (_gate) _revoked.Add(Key(packageId ?? "", version ?? ""));
        Changed?.Invoke();
    }

    /// <summary>bd-shared-plat-1/F2: the audited, actor-gated
    /// revocation. The actor must be named and the supplied admin
    /// check must pass; every successful revocation appends to the
    /// chained audit log. The parameterless overload above remains
    /// ONLY for persistence restore / bootstrap construction (it is
    /// used by ImportJson's revocation-set restore path through the
    /// set itself, never as an operator act).</summary>
    public (bool Ok, string Reason) Revoke(string packageId, string version, string actor,
        Func<string, bool> isAdminActor, ChainedAuditLog? audit, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(actor))
            return (false, "revocation needs a named actor — refused");
        if (isAdminActor is null || !isAdminActor(actor))
            return (false, $"actor '{actor}' holds no admin right for revocation — refused");
        Revoke(packageId, version);
        audit?.Append("package_revoked", actor,
            $"package={packageId} v{version} revoked by {actor} (deploy-time refusal now applies in the hub service AND in DeploymentRunner)", now);
        return (true, $"package '{packageId}' v{version} revoked by '{actor}'");
    }

    public bool IsRevoked(string packageId, string version)
    {
        lock (_gate) return _revoked.Contains(Key(packageId ?? "", version ?? ""));
    }

    /// <summary>Lane A: raised after every successful mutation so
    /// CoreRuntime can write the repository through to disk.</summary>
    public event Action? Changed;

    // ---- hub persistence (Lane A: RMM-04 pattern + integrity envelope) ----
    // Packages persist as their canonical JSON (the signed-delivery
    // shape) + the revocation set. Licence VALUES never persist
    // here: they live only in the PackageSecretVault. On import a
    // package is re-admitted through the SAME whole-package gate
    // (validation + manifest + vault agreement), so a package whose
    // licences the vault does not hold is refused at restore too.

    public string ExportJson()
    {
        lock (_gate)
        {
            var pkgs = _byKey.Values
                .OrderBy(p => p.Id, StringComparer.Ordinal).ThenBy(p => p.Version, StringComparer.Ordinal)
                .Select(p => p.ToCanonicalJson()).ToList();
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                Packages = pkgs,
                Revoked = _revoked.OrderBy(r => r, StringComparer.Ordinal).ToList(),
            });
            return Acp.Shared.Hub.HubPersistence.Wrap("acp-package-repository-v1", payload);
        }
    }

    public int ImportJson(string json)
    {
        var payload = Acp.Shared.Hub.HubPersistence.Unwrap(json, "acp-package-repository-v1");
        if (payload is null) return 0;
        List<string> pkgJsons; List<string> revoked;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(payload);
            pkgJsons = doc.RootElement.GetProperty("Packages").EnumerateArray()
                .Select(e => e.GetString() ?? "").ToList();
            revoked = doc.RootElement.TryGetProperty("Revoked", out var rev)
                ? rev.EnumerateArray().Select(e => e.GetString() ?? "").ToList()
                : new List<string>();
        }
        catch { return 0; }
        var restored = 0;
        foreach (var pj in pkgJsons)
        {
            DeploymentPackage? pkg;
            try { pkg = DeploymentPackage.FromCanonicalJson(pj); } catch { continue; }
            if (pkg is null) continue;
            var before = Count;
            var (admitted, _) = Admit(pkg);
            if (admitted && Count > before) restored++;
        }
        lock (_gate)
        {
            foreach (var r in revoked)
                if (!string.IsNullOrWhiteSpace(r)) _revoked.Add(r);
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }

    /// <summary>Secret-free listings for every admitted version.</summary>
    public IReadOnlyList<PackageListing> Listings()
    {
        lock (_gate) return _byKey.Values
            .OrderBy(p => p.Id, StringComparer.Ordinal).ThenBy(p => p.Version, StringComparer.Ordinal)
            .Select(p => new PackageListing(p.Id, p.Version, p.Name, p.Enabled,
                _revoked.Contains(Key(p.Id, p.Version)), p.ContentHash, p.Files.Count,
                p.LicenceKeys.Select(l => l.Ref).ToList(),
                p.LicenceKeys.Select(l => l.Fingerprint).ToList(),
                p.Install.Steps.Count, p.Uninstall.Steps.Count)).ToList();
    }
}

// ---- content packs ---------------------------------------------------

/// <summary>A versioned bundle of packages — the ComStore /
/// Automation-Exchange shape as local data. Packs travel inside an
/// RMM-03 policy_delivery envelope (the RMM-08 library pattern) and
/// are revision-monotonic per pack id. A pack is a DISTRIBUTION
/// unit: admitting a pack admits each of its packages into the
/// repository through the same whole-package gate.</summary>
public sealed record ContentPack(string Id, long Revision, IReadOnlyList<DeploymentPackage> Packages)
{
    public IReadOnlyList<DeploymentPackage> Packages { get; init; } = Packages ?? Array.Empty<DeploymentPackage>();

    public string ToCanonicalJson()
    {
        var pkgs = string.Join(",", Packages.OrderBy(p => p.Id, StringComparer.Ordinal)
            .Select(p => p.ToCanonicalJson()));
        return "{\"id\":" + JsonSerializer.Serialize(Id) + ",\"revision\":" + Revision +
               ",\"packages\":[" + pkgs + "]}";
    }

    public string ContentHash => PackageHashing.Sha256Hex(ToCanonicalJson());

    public static ContentPack? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var packs = new List<DeploymentPackage>();
            foreach (var el in root.GetProperty("packages").EnumerateArray())
            {
                var pkg = DeploymentPackage.FromCanonicalJson(el.GetRawText());
                if (pkg is null) return null;
                packs.Add(pkg);
            }
            return new ContentPack(root.GetProperty("id").GetString() ?? "",
                root.GetProperty("revision").GetInt64(), packs);
        }
        catch { return null; }
    }

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > PackageLimits.MaxIdLength)
            return "content pack needs an id within bounds — refused";
        if (Revision < 1) return $"content pack '{Id}' revision {Revision} is not positive — refused";
        if (Packages.Count == 0) return $"content pack '{Id}' carries no packages — refused (an empty pack is a false promise)";
        if (Packages.Count > PackageLimits.MaxPackagesPerPack)
            return $"content pack '{Id}' carries {Packages.Count} packages over the cap {PackageLimits.MaxPackagesPerPack} — refused";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Packages)
        {
            if (!seen.Add($"{p.Id}@{p.Version}"))
                return $"content pack '{Id}': duplicate package '{p.Id}' v{p.Version} — refused";
            if (p.Validate() is { } bad) return $"content pack '{Id}': {bad}";
        }
        return null;
    }
}

/// <summary>The starter content packs — honest, generic, local.
/// Runtime/utility packs ship ENABLED with generic steps. The BAS
/// workstation pack ships DISABLED as TEMPLATES: its steps carry
/// placeholder site facts (&lt;SITE_…&gt;) that a signed site
/// revision must replace — ACP never guesses a site's service
/// account, licence server, or install share (RMM-01/08 pattern).
/// Licence-bound starter packages bind NO real keys: the BAS
/// template's licence ref is a placeholder the site's vault entry
/// must satisfy before admission can succeed at all.</summary>
public static class StarterContentPacks
{
    public const string RuntimePackId = "acp-starter-runtimes";
    public const string UtilitiesPackId = "acp-starter-utilities";
    public const string BasWorkstationPackId = "acp-starter-bas-workstation";

    private static AutomationDefinition Def(string id, string name, string description,
        bool enabled, params RemediationStep[] steps) =>
        // RMM-08 D38-F11 admission discipline: definitions carrying
        // high-impact kinds (run_script / uninstall_app — every
        // starter install/uninstall) must be authored at the
        // requires_approval tier; tier-auto definitions with those
        // kinds refuse at AutomationLibrary admission, which the
        // package probe reuses. Installers are high-impact by
        // nature, so the tier is honest, not a workaround.
        AutomationDefinition.Create(id, name, steps, tier: RemediationTiers.RequiresApproval,
            enabled: enabled, description: description,
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    /// <summary>All starter packs (code-seeded, part of the signed
    /// build — content, not behaviour).</summary>
    public static IReadOnlyList<ContentPack> All() => new[] { RuntimePack(), UtilitiesPack(), BasWorkstationPack() };

    public static ContentPack RuntimePack() => new(RuntimePackId, 1, new[]
    {
        new DeploymentPackage(
            // W9 verification (bd-shared-plat-1/F8 remainder, closed
            // 2026-11-23): the pin is REAL. .NET Desktop Runtime
            // 8.0.0 is Microsoft's GA release of the 8.0 line
            // (dotnet.microsoft.com download pages for
            // runtime-desktop-8.0.0, Windows x64 installer; the SDK
            // 8.0.100 included-runtimes list names ".NET Desktop
            // Runtime 8.0.0"), and Microsoft Learn's .NET install
            // documentation lists Microsoft.DotNet.DesktopRuntime.8
            // as the winget package for ".NET Desktop Runtime 8.0" —
            // so "--version 8.0.0 --exact" names an installable
            // catalogue version of that package, not a guess.
            // Residual, stated plainly: the literal winget-pkgs
            // manifest folder was not re-read this wave; the claim
            // rests on Microsoft's own release + package pages.
            // Note also: the 8.0 line reached end of life
            // 2026-11-10 — this starter pin is a FLOOR for legacy
            // workstation tooling, not a currency claim.
            "dotnet-desktop-runtime", "8.0.0", ".NET Desktop Runtime 8",
            "Standard runtime install (winget shape): the runtime most BAS workstation tooling needs. Generic — no site facts.",
            true, ".NET Desktop Runtime 8",
            Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
            Def("dotnet-desktop-runtime-install", "Install .NET Desktop Runtime 8", "winget install", true,
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    // D38-F11: the version is PINNED to the package's
                    // declared version — an unpinned winget install
                    // takes whatever is latest, so the recorded
                    // version could never match the observed one.
                    scriptBody: "winget install --id Microsoft.DotNet.DesktopRuntime.8 --version 8.0.0 --exact --silent --accept-package-agreements --accept-source-agreements")),
            Def("dotnet-desktop-runtime-uninstall", "Uninstall .NET Desktop Runtime 8", "winget uninstall", true,
                RemediationStep.Create("uninstall", RemediationStepKinds.RunScript,
                    scriptBody: "winget uninstall --id Microsoft.DotNet.DesktopRuntime.8 --exact --silent"))),
        new DeploymentPackage(
            // bd-shared-plat-1/F8: the winget catalogue version for
            // the 14.40 build is the FULL build number
            // (14.40.33810.0) — "--version 14.40.0 --exact" matches
            // no catalogue entry and could never install.
            "vcredist-x64", "14.40.33810.0", "Visual C++ Redistributable x64",
            "Standard VC++ runtime prerequisite for vendor workstation tools. Generic — no site facts.",
            // D38-F11: the real Add/Remove Programs name — the old
            // "Microsoft Visual C++ v14 Redistributable (x64)" matches
            // nothing Windows reports, so convergence could never
            // observe this package. (The ARP entry carries a
            // " - <version>" suffix; DeploymentConvergence matches
            // that shape.)
            true, "Microsoft Visual C++ 2015-2022 Redistributable (x64)",
            Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
            Def("vcredist-x64-install", "Install VC++ Redistributable x64", "winget install", true,
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "winget install --id Microsoft.VCRedist.2015+.x64 --version 14.40.33810.0 --exact --silent --accept-package-agreements --accept-source-agreements")),
            Def("vcredist-x64-uninstall", "Uninstall VC++ Redistributable x64", "winget uninstall", true,
                RemediationStep.Create("uninstall", RemediationStepKinds.RunScript,
                    scriptBody: "winget uninstall --id Microsoft.VCRedist.2015+.x64 --exact --silent"))),
    });

    public static ContentPack UtilitiesPack() => new(UtilitiesPackId, 1, new[]
    {
        new DeploymentPackage(
            // bd-shared-plat-1/F8: winget's 7-Zip versions are
            // "24.09"-shaped (no 24.0.0 exists in the catalogue),
            // and the real ARP entry is "7-Zip 24.09 (x64)" — the
            // old bare "7-Zip" name + 24.0.0 pin could neither
            // install exactly nor ever be observed by convergence.
            "seven-zip", "24.09", "7-Zip",
            "Standard archive utility — the generic site-toolbox install. No site facts.",
            true, "7-Zip 24.09 (x64)",
            Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
            Def("seven-zip-install", "Install 7-Zip", "winget install", true,
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "winget install --id 7zip.7zip --version 24.09 --exact --silent --accept-package-agreements --accept-source-agreements")),
            Def("seven-zip-uninstall", "Uninstall 7-Zip", "winget uninstall", true,
                RemediationStep.Create("uninstall", RemediationStepKinds.RunScript,
                    scriptBody: "winget uninstall --id 7zip.7zip --exact --silent"))),
    });

    /// <summary>The BAS workstation prerequisites pack: TEMPLATES,
    /// disabled, placeholder site facts. The licence ref
    /// ("bas-suite-licence") must exist in the site vault with a
    /// value whose hash the site's signed package revision binds —
    /// this code-seeded template binds the hash of a PLACEHOLDER
    /// value, so it cannot be admitted against a real vault until a
    /// site revision re-binds it. That is deliberate: the template
    /// is a shape to fill in, never a deployable guess.</summary>
    public static ContentPack BasWorkstationPack()
    {
        var placeholderHash = PackageHashing.Sha256Hex("<SITE_LICENCE_KEY_PLACEHOLDER>");
        return new ContentPack(BasWorkstationPackId, 1, new[]
        {
            new DeploymentPackage(
                "bas-workstation-suite", "1.0.0", "BAS workstation suite (TEMPLATE)",
                "TEMPLATE — multi-step BAS workstation install: pre-step stops the site service, install consumes the site licence key from the vault, post-step restarts the service. Ships DISABLED with placeholder site facts; a signed site revision must replace every <SITE_…> placeholder and re-bind the real licence hash before this can deploy.",
                false, "<SITE_BAS_SUITE_SOFTWARE_NAME>",
                Array.Empty<PackageFileComponent>(),
                new[] { new PackageLicenceComponent("bas-suite-licence", placeholderHash) },
                Def("bas-workstation-suite-install", "Install BAS workstation suite (template)", "template", false,
                    RemediationStep.Create("pre-stop-service", RemediationStepKinds.StopService, target: "<SITE_BAS_SERVICE_NAME>"),
                    RemediationStep.Create("install", RemediationStepKinds.RunScript,
                        scriptBody: @"<SITE_INSTALL_SHARE>\bas-suite-setup.exe /quiet /licence {licence:bas-suite-licence}"),
                    RemediationStep.Create("post-start-service", RemediationStepKinds.StartService, target: "<SITE_BAS_SERVICE_NAME>")),
                Def("bas-workstation-suite-uninstall", "Uninstall BAS workstation suite (template)", "template", false,
                    RemediationStep.Create("pre-stop-service", RemediationStepKinds.StopService, target: "<SITE_BAS_SERVICE_NAME>"),
                    RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "<SITE_BAS_SUITE_SOFTWARE_NAME>"))),
        });
    }

    /// <summary>The starter packs as distributable FILES (the
    /// user-owned-repo shape): filename → canonical JSON bytes. A
    /// site drops these into its own repo; the hub admits them
    /// through the same signed-delivery gate as any pack.</summary>
    public static IReadOnlyDictionary<string, byte[]> AsFiles() =>
        All().ToDictionary(p => $"content-pack-{p.Id}-r{p.Revision}.json",
            p => Encoding.UTF8.GetBytes(p.ToCanonicalJson()));
}
