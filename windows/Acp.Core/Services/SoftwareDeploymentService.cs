using System.Text;
using Acp.Shared.Deployment;
using Acp.Shared.Distribution;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Core.Services;

// =====================================================================
// RMM-16 — SoftwareDeploymentService: the hub-side deployment
// surface over PackageRepository + DeploymentRunner.
//
// Deploy path, in order, every refusal a chained audit event:
//   1. Device facts resolve (policy cannot be evaluated without
//      them — fail closed).
//   2. TOTAL POLICY CONTROL: `rmm.software_deployment.enabled` for
//      the device via RMM-07, plus the per-package enable setting.
//      OFF refuses; the RMM-08 engine additionally re-checks the
//      global toggle before every step (mid-flight kill).
//   3. The package version is admitted, not revoked, and enabled.
//   4. TARGETING: an assignment (DeploymentAssignment) must cover
//      this device for this package version — deployment by policy
//      means no assignment, no deployment, and a device outside
//      the target set refuses by name (the targeting-escape attack).
//   5. DOWNGRADE: an older version over a recorded newer install
//      refuses unless a named human downgrade decision is supplied;
//      the decision is bound into the signed payload and audited.
//   6. Payloads: file components are fetched into the endpoint
//      content store through RMM-14 (the PayloadFetcher seam —
//      ContentFetcher over the coordinator's ordering, hub last)
//      when wired; the runner re-verifies store contents regardless.
//   7. Execution: the service mints the RMM-03 package_deploy
//      envelope binding package/device/action/downgrade bit, plus
//      the inner automation + script_exec envelopes the RMM-08
//      engine and RMM-15 journal verify; DeploymentRunner runs it.
//      The deployment id is service-generated and doubles as the
//      inner execution's alert id, so the inner binding is exact.
//
// Uninstall is the same path with action=uninstall and one extra
// gate, checked before anything is minted: a device with no
// recorded deployment of the package refuses — an uninstall
// command for a package never deployed is a forgery shape, not a
// no-op.
//
// Repository + content-pack admission arrive ONLY as signed
// content (policy_delivery, the RMM-08 library pattern) or the
// audited local path; pack admission is whole-pack and
// revision-disciplined. State (assignments, per-device deployment
// records, pack revisions) is in-memory here, but it round-trips
// through ExportStateJson/ImportStateJson (HubPersistence
// integrity envelope — D38-F6, so a hub restart no longer resets
// the downgrade and uninstall-forgery checks to "nothing
// installed"); the host's write-through wiring remains the
// wiring's step, exactly as RemediationService leaves journal
// persistence to its wiring. Deploy-time integrity is anchored to
// admission: ExecuteDeployment compares the package against the
// repository's admitted content hash and passes that anchor to
// the runner (D38-F1/F2).
// =====================================================================

public sealed record DeploymentDispatchResult(bool Dispatched, string Outcome, DeploymentExecution? Execution);

public sealed class SoftwareDeploymentService
{
    private static readonly TimeSpan EnvelopeTtl = TimeSpan.FromMinutes(5);

    /// <summary>D38-F12b: bound on the retained in-memory execution
    /// history (newest kept).</summary>
    public const int MaxRetainedExecutions = 256;

    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly SignedCommandSigner? _signer;
    private readonly SignedCommandGate? _gate;
    private readonly PackageRepository _repository;
    private readonly PackageSecretVault _vault;
    private readonly DeploymentRunner _runner;
    private readonly JobJournal _journal;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private readonly List<DeploymentAssignment> _assignments = new();
    private readonly Dictionary<string, DevicePackageState> _state = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _packRevisions = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<DeploymentExecution> _executions = new();

    /// <summary>Optional RMM-14 fetch seam: given a package and a
    /// device, fetch any missing file payloads into the endpoint
    /// store and return it (null = no seam wired; packages with
    /// file components then refuse rather than deploy fileless).
    /// Wired by the Core host with ContentFetcher +
    /// HubDistributionCoordinator.</summary>
    public Func<DeploymentPackage, string, PeerContentStore?>? PayloadFetcher { get; set; }

    /// <summary>bd-shared-plat-1/F4: post-install inventory probe —
    /// (package, deviceId) → the version inventory NOW observes
    /// for the package (null = not observed). Passed to the runner
    /// so verify_install reads real installed state. When unwired,
    /// verify_install fails honestly and the deployment lands as
    /// partial_failure instead of claiming a verified install.</summary>
    public Func<DeploymentPackage, string, string?>? InstalledVersionProbe { get; set; }

    public SoftwareDeploymentService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        SignedCommandSigner? signer,
        SignedCommandGate? gate,
        PackageRepository repository,
        PackageSecretVault vault,
        IRemediationStepExecutor executor,
        JobJournal? journal = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _signer = signer;
        _gate = gate;
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _journal = journal ?? new JobJournal(null,
            (kind, actor, detail) => _audit.Append(kind, actor ?? "software-deployment-service", detail ?? "", _now()));
        _runner = new DeploymentRunner(
            executor ?? throw new ArgumentNullException(nameof(executor)), gate, audit, vault);
    }

    public PackageRepository Repository => _repository;
    public JobJournal Journal => _journal;

    public IReadOnlyList<DeploymentExecution> Executions
    {
        get { lock (_lock) return _executions.ToList(); }
    }

    public IReadOnlyList<DeploymentAssignment> Assignments
    {
        get { lock (_lock) return _assignments.ToList(); }
    }

    public DevicePackageState? StateFor(string deviceId, string packageId)
    {
        lock (_lock) return _state.TryGetValue(StateKey(deviceId, packageId), out var s) ? s : null;
    }

    private static string StateKey(string deviceId, string packageId) => $"{deviceId}|{packageId}";

    public bool IsDeploymentEnabled(IDeviceFacts facts) =>
        _policy.IsEnabled(facts, DeploymentPolicyKeys.DeploymentEnabled);

    // ---- repository / pack admission --------------------------------

    /// <summary>Apply a package delivered as a signed envelope
    /// (class policy_delivery). Verification precedes parsing; the
    /// payload is the package's canonical JSON, whose embedded
    /// manifest is the expected manifest admission recomputes
    /// against.</summary>
    public PolicyVerdict ApplySignedPackage(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured — signed package delivery refuses (RMM-03)";
            _audit.Append("package_delivery_refused", "software-deployment-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        DeploymentPackage? package;
        try { package = DeploymentPackage.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { package = null; }
        if (package is null)
        {
            const string reason = "signed payload did not parse as a deployment package — refused";
            _audit.Append("package_delivery_refused", "software-deployment-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        // D38-F1: the expected manifest is the one EMBEDDED in the
        // signed JSON (CarriedManifest) — the old code passed
        // package.Manifest(), a manifest recomputed from the very
        // components under test, so the check could never fail.
        return AdmitPackage(package, package.CarriedManifest, "signed delivery");
    }

    /// <summary>Admit from an already-trusted local path (tests,
    /// starter-pack seeding). The same whole-package gate applies.</summary>
    public PolicyVerdict AdmitLocalPackage(DeploymentPackage package, string via) =>
        AdmitPackage(package, null, via);

    private PolicyVerdict AdmitPackage(DeploymentPackage package,
        IReadOnlyList<ComponentBinding>? expectedManifest, string via)
    {
        var now = _now();
        var (admitted, reason) = _repository.Admit(package, expectedManifest);
        _audit.Append(admitted ? "package_admitted" : "package_refused", "software-deployment-service",
            $"package={package.Id} v{package.Version} via={via}{(admitted ? "" : $" reason={reason}")}", now);
        return new PolicyVerdict(admitted, reason);
    }

    /// <summary>Apply a content pack delivered as a signed envelope
    /// (class policy_delivery). Revision discipline is per pack id;
    /// every package in the pack passes the repository gate or the
    /// pack applies NONE of them (whole-pack admission).</summary>
    public PolicyVerdict ApplySignedContentPack(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured — signed content-pack delivery refuses (RMM-03)";
            _audit.Append("content_pack_refused", "software-deployment-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        ContentPack? pack;
        try { pack = ContentPack.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { pack = null; }
        if (pack is null)
        {
            const string reason = "signed payload did not parse as a content pack — refused";
            _audit.Append("content_pack_refused", "software-deployment-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return AdmitContentPack(pack, "signed delivery");
    }

    public PolicyVerdict AdmitLocalContentPack(ContentPack pack, string via) => AdmitContentPack(pack, via);

    private PolicyVerdict AdmitContentPack(ContentPack pack, string via)
    {
        var now = _now();
        PolicyVerdict RefusePack(string reason)
        {
            _audit.Append("content_pack_refused", "software-deployment-service",
                $"pack={pack.Id} r{pack.Revision} via={via} reason={reason}", now);
            return new PolicyVerdict(false, reason);
        }
        if (pack.Validate() is { } invalid) return RefusePack(invalid);
        // D38-F8: the WHOLE pack operation — revision check,
        // pre-check, admission, revision write — runs under the
        // service lock, and admission itself is the repository's
        // atomic AdmitAll (which pre-checks the cap and conflicts
        // for the whole batch before storing any). The old shape
        // released the lock between revision check and write (two
        // concurrent same-revision packs could both pass) and
        // admitted per-package with an early return (a refusal at
        // the repository cap left the pack half-admitted while
        // reported refused).
        lock (_lock)
        {
            if (_packRevisions.TryGetValue(pack.Id, out var current))
            {
                if (pack.Revision < current)
                    return RefusePack($"content pack '{pack.Id}' revision {pack.Revision} is stale (current {current}) — refused");
                if (pack.Revision == current)
                {
                    var identical = pack.Packages.All(p =>
                    {
                        var existing = _repository.Get(p.Id, p.Version);
                        return existing is not null && existing.ContentHash == p.ContentHash;
                    });
                    if (!identical)
                        return RefusePack($"content pack '{pack.Id}' revision {pack.Revision} conflicts with the admitted pack of the same id+revision — refused");
                    return new PolicyVerdict(true, $"content pack '{pack.Id}' r{pack.Revision} already admitted (idempotent)");
                }
            }
            // Pre-check EVERY package before admitting any (whole-pack).
            foreach (var pkg in pack.Packages)
            {
                var existing = _repository.Get(pkg.Id, pkg.Version);
                if (existing is not null && existing.ContentHash != pkg.ContentHash)
                    return RefusePack($"package '{pkg.Id}' v{pkg.Version} conflicts with the admitted package of the same id+version — pack refused whole");
                foreach (var lic in pkg.LicenceKeys)
                {
                    var vaultHash = _vault.HashOf(lic.Ref);
                    if (vaultHash is null || !string.Equals(vaultHash, lic.ValueHash, StringComparison.OrdinalIgnoreCase))
                        return RefusePack($"package '{pkg.Id}' v{pkg.Version}: licence '{lic.Ref}' does not agree with the vault — pack refused whole (a pack never smuggles a key past the vault gate)");
                }
            }
            var (ok, reason) = _repository.AdmitAll(pack.Packages);
            if (!ok) return RefusePack(reason);
            _packRevisions[pack.Id] = pack.Revision;
        }
        _audit.Append("content_pack_admitted", "software-deployment-service",
            $"pack={pack.Id} revision={pack.Revision} packages={pack.Packages.Count} via={via}", now);
        return new PolicyVerdict(true, $"content pack '{pack.Id}' r{pack.Revision} admitted via {via} ({pack.Packages.Count} packages)");
    }

    /// <summary>Seed the code-shipped starter packs through the
    /// local path. The BAS workstation template pack REFUSES
    /// against any real vault (its placeholder licence hash matches
    /// no real key) — that refusal is the designed behaviour,
    /// returned per pack, never hidden.</summary>
    public IReadOnlyList<(string PackId, PolicyVerdict Verdict)> SeedStarterPacks()
    {
        var results = new List<(string, PolicyVerdict)>();
        foreach (var pack in StarterContentPacks.All())
            results.Add((pack.Id, AdmitLocalContentPack(pack, "starter seed")));
        return results;
    }

    // ---- targeting ----------------------------------------------------

    /// <summary>Register/replace a policy targeting assignment for
    /// one package version. Audited: targeting IS policy.</summary>
    public void Assign(string packageId, string version, IEnumerable<string> groupIds, string assignedBy)
    {
        var assignment = new DeploymentAssignment(packageId, version, groupIds.ToList());
        lock (_lock)
        {
            // D38-F10: an assignment names THE desired version of a
            // package — assigning a new version supersedes every
            // older assignment for that package id (the old
            // id+version match let assignments pile up per version:
            // 1.0.0 stayed targeted and deployable after 2.0.0 was
            // assigned, and convergence emitted contradictory lines
            // for one package). D38-F9c: the id match is
            // case-insensitive, like the repository and state stores
            // — Assign("Widget", …) must not silently target nothing.
            _assignments.RemoveAll(a =>
                string.Equals(a.PackageId, packageId, StringComparison.OrdinalIgnoreCase));
            _assignments.Add(assignment);
        }
        _audit.Append("deployment_assignment_set", assignedBy,
            $"package={packageId} v{version} groups={string.Join(",", assignment.GroupIds)}", _now());
    }

    private bool IsTargeted(DeploymentPackage package, IDeviceFacts facts)
    {
        List<DeploymentAssignment> assignments;
        lock (_lock) assignments = _assignments
            .Where(a => string.Equals(a.PackageId, package.Id, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(a.Version, package.Version, StringComparison.OrdinalIgnoreCase)).ToList();
        if (assignments.Count == 0) return false;
        var groups = _policy.Groups;
        return assignments.Any(a => a.Targets(facts, groups));
    }

    // ---- deploy / uninstall --------------------------------------------

    public DeploymentDispatchResult Deploy(string packageId, string version, string deviceId,
        DateTimeOffset now, string? downgradeDecidedBy = null)
    {
        DeploymentDispatchResult Refuse(string reason)
        {
            _audit.Append("deployment_dispatch_refused", "software-deployment-service",
                $"package={packageId} v{version} device={deviceId} action=deploy reason={reason}", now);
            return new DeploymentDispatchResult(false, reason, null);
        }

        var package = _repository.Get(packageId, version);
        if (package is null)
            return Refuse($"package '{packageId}' v{version} is not in the repository — refused");
        if (Prepare(package, deviceId) is { } prepRefusal) return Refuse(prepRefusal);

        var recorded = StateFor(deviceId, packageId);
        // D38-F5/F6: a partially deployed package IS installed for
        // downgrade purposes — its steps ran on the device.
        var installedVersion = recorded is { Status: DevicePackageState.Deployed or DevicePackageState.PartiallyDeployed }
            ? recorded.InstalledVersion : null;
        var downgradeApproved = false;
        if (installedVersion is not null && SoftwareVersion.Compare(version, installedVersion) < 0)
        {
            if (string.IsNullOrWhiteSpace(downgradeDecidedBy))
                return Refuse($"downgrade refused: v{version} is older than the installed v{installedVersion} on '{deviceId}' and no downgrade decision was supplied — refused (redeploying an older signed version over a newer install needs a named human decision)");
            downgradeApproved = true;
            _audit.Append("deployment_downgrade_decided", downgradeDecidedBy,
                $"package={packageId} from v{installedVersion} to v{version} device={deviceId} — explicit downgrade decision, bound into the signed deployment", now);
        }
        return ExecuteDeployment(package, deviceId, DeploymentActions.Deploy, downgradeApproved,
            installedVersion, now, Refuse);
    }

    public DeploymentDispatchResult Uninstall(string packageId, string deviceId, DateTimeOffset now)
    {
        DeploymentDispatchResult Refuse(string reason)
        {
            _audit.Append("deployment_dispatch_refused", "software-deployment-service",
                $"package={packageId} device={deviceId} action=uninstall reason={reason}", now);
            return new DeploymentDispatchResult(false, reason, null);
        }

        // Uninstall forgery gate: no recorded deployment, no
        // uninstall — checked before anything is minted. A
        // PARTIALLY deployed package (D38-F5) counts: steps ran,
        // the device changed, uninstall must be possible.
        var recorded = StateFor(deviceId, packageId);
        if (recorded is null || (recorded.Status != DevicePackageState.Deployed &&
                                 recorded.Status != DevicePackageState.PartiallyDeployed))
            return Refuse($"uninstall refused: package '{packageId}' has no recorded deployment on '{deviceId}' — an uninstall command for a package never deployed is refused, not executed as a no-op");
        var package = _repository.Get(packageId, recorded.InstalledVersion);
        if (package is null)
            return Refuse($"package '{packageId}' v{recorded.InstalledVersion} (the deployed version) is no longer in the repository — uninstall refused rather than guessed");
        if (Prepare(package, deviceId, forUninstall: true) is { } prepRefusal) return Refuse(prepRefusal);
        return ExecuteDeployment(package, deviceId, DeploymentActions.Uninstall, false,
            recorded.InstalledVersion, now, Refuse);
    }

    /// <summary>Shared gates: facts, policy (global + per-package),
    /// revoked, targeting. Null when the deployment may proceed;
    /// otherwise the refusal reason.
    /// D38-F4: UNINSTALL runs a reduced gate — facts + the global
    /// policy toggle only. Revocation, a per-package disable, or a
    /// removed/retargeted assignment must never block pulling a
    /// package OFF a device: the case where an operator most needs
    /// uninstall (a bad package, revoked for cause) was exactly the
    /// case the old shared gate refused. The global toggle stays:
    /// it is the operator's master stop for the whole surface.</summary>
    private string? Prepare(DeploymentPackage package, string deviceId, bool forUninstall = false)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return $"no device facts for '{deviceId}' — policy cannot be evaluated — refused (fail closed)";
        if (!IsDeploymentEnabled(facts))
            return $"software deployment is disabled by policy for this device ({DeploymentPolicyKeys.DeploymentEnabled}) — refused; the policy toggle is the deployment kill switch";
        if (forUninstall) return null;
        var perPackage = _policy.ComputeEffective(facts).Get(DeploymentPolicyKeys.PackageEnabled(package.Id));
        if (perPackage is not null && (!bool.TryParse(perPackage.Value, out var enabled) || !enabled))
            return $"package '{package.Id}' is disabled for this device by policy ({DeploymentPolicyKeys.PackageEnabled(package.Id)}) — refused";
        if (_repository.IsRevoked(package.Id, package.Version))
            return $"package '{package.Id}' v{package.Version} is revoked — refused (a pulled package deploys nowhere, however valid its signature)";
        if (!IsTargeted(package, facts))
            return $"device '{deviceId}' is outside the policy target set for package '{package.Id}' v{package.Version} — refused (deployment by policy: no assignment covering this device, no deployment)";
        return null;
    }

    private DeploymentDispatchResult ExecuteDeployment(DeploymentPackage package, string deviceId,
        string action, bool downgradeApproved, string? installedVersion, DateTimeOffset now,
        Func<string, DeploymentDispatchResult> refuse)
    {
        if (_signer is null)
            return refuse("no customer command signer is configured on the hub — deployment cannot mint its RMM-03 package_deploy envelope — refused");
        if (_gate is null)
            return refuse("no signed-command gate is configured — deployment refuses (RMM-03)");

        // D38-F2: anchor this deployment to what ADMISSION recorded.
        // The package object is compared against the repository's
        // own admitted hash BEFORE anything is signed, and the
        // anchor is passed to the runner, which re-checks it
        // endpoint-side — the old path signed whatever the
        // repository currently returned, so a tampered repository
        // was signed fresh and ran.
        var admittedHash = _repository.AdmittedContentHash(package.Id, package.Version);
        if (admittedHash is null ||
            !string.Equals(admittedHash, package.ContentHash, StringComparison.OrdinalIgnoreCase))
            return refuse($"package '{package.Id}' v{package.Version} does not match the content hash recorded at admission — refused (the repository was tampered with between admission and deploy)");

        // RMM-14 payload leg: file components must be present in a
        // verified endpoint store before the runner will execute.
        PeerContentStore? store = null;
        if (package.Files.Count > 0)
        {
            store = PayloadFetcher?.Invoke(package, deviceId);
            if (store is null)
                return refuse($"package '{package.Id}' v{package.Version} carries {package.Files.Count} file component(s) but no RMM-14 payload seam is wired to fetch them — refused rather than deploying without its files");
        }

        var deploymentId = Guid.NewGuid().ToString("N");
        var envelope = _signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(package, deviceId, action, downgradeApproved)),
            now, EnvelopeTtl);
        var def = DeploymentBinding.DefinitionFor(package, action);
        var library = DeploymentBinding.ExecutionLibrary(package, action);
        var automationEnvelope = _signer.Sign(SignedCommandClasses.Automation,
            // The v2 RMM-08 binding includes the alert condition;
            // the runner's synthetic alert carries
            // DeploymentBinding.AlertConditionId, so the mint must
            // name it too (RemediationService does the same with
            // its alert's condition).
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, library, deviceId, deploymentId,
                DeploymentBinding.AlertConditionId)),
            now, EnvelopeTtl);
        var journalEnvelope = _signer.Sign(SignedCommandClasses.ScriptExec,
            Encoding.UTF8.GetBytes($"script_chain|{def.Id}|{RemediationBinding.PlanHash(def)}"),
            now, EnvelopeTtl);
        var facts = _factsByDevice(deviceId)!;
        var execution = _runner.Run(package, deviceId, action, downgradeApproved,
            envelope, automationEnvelope, journalEnvelope, _journal,
            policyStillEnabled: () => IsDeploymentEnabled(facts),
            installedVersion, store, deploymentId, now,
            expectedContentHash: admittedHash,
            // bd-shared-plat-1/F2+F4: the runner itself re-checks
            // revocation and reads post-install state.
            isRevoked: _repository.IsRevoked,
            installedVersionProbe: InstalledVersionProbe is null
                ? null
                : pkg => InstalledVersionProbe(pkg, deviceId));
        lock (_lock)
        {
            _executions.Add(execution);
            // D38-F12b: the retained execution history is BOUNDED
            // (newest kept) — the old list grew without limit for
            // the life of the hub process.
            if (_executions.Count > MaxRetainedExecutions)
                _executions.RemoveRange(0, _executions.Count - MaxRetainedExecutions);
        }
        if (execution.Outcome == DeploymentOutcomes.Refused)
            return new DeploymentDispatchResult(false, $"execution refused (see audit): deployment={execution.DeploymentId}", execution);
        if (execution.Outcome == DeploymentOutcomes.Succeeded)
        {
            lock (_lock)
            {
                _state[StateKey(deviceId, package.Id)] = action == DeploymentActions.Deploy
                    ? new DevicePackageState(deviceId, package.Id, package.Version, DevicePackageState.Deployed, now)
                    : new DevicePackageState(deviceId, package.Id, package.Version, DevicePackageState.Uninstalled, now);
            }
        }
        else if (execution.Outcome == DeploymentOutcomes.PartialFailure || execution.AnyStepExecuted)
        {
            // D38-F5: steps ran, so the device CHANGED even though
            // the deployment did not fully succeed. Record it as
            // partially deployed: uninstall stays possible (it is
            // not refused as a forgery) and the downgrade rule can
            // see the version that is actually on the device. A
            // partial UNINSTALL likewise leaves the package
            // partially present, never "uninstalled".
            lock (_lock)
            {
                _state[StateKey(deviceId, package.Id)] =
                    new DevicePackageState(deviceId, package.Id, package.Version,
                        DevicePackageState.PartiallyDeployed, now);
            }
            _audit.Append("deployment_state_partial", "software-deployment-service",
                $"package={package.Id} v{package.Version} device={deviceId} action={action} outcome={execution.Outcome} — steps executed; recorded as partially deployed so uninstall and the downgrade rule see the changed device", now);
        }
        return new DeploymentDispatchResult(execution.Outcome == DeploymentOutcomes.Succeeded,
            $"deployment={execution.DeploymentId} outcome={execution.Outcome} job={execution.JobId ?? "(none)"}", execution);
    }

    // ---- state persistence (D38-F6) --------------------------------------
    // The downgrade rule and the uninstall-forgery gate read the
    // recorded deployment state; when that state was purely
    // in-memory, a hub restart silently reset BOTH checks to
    // "nothing installed" (the old residual named only the
    // uninstall side). The state now round-trips through the same
    // HubPersistence integrity envelope the repository uses
    // (RMM-04 pattern), so the Core wiring can persist it exactly
    // like the repository. Wiring the write-through in the host
    // remains the wiring step; the mechanism + round-trip are
    // proven here.

    public string ExportStateJson()
    {
        lock (_lock)
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                Assignments = _assignments.Select(a => new
                { a.PackageId, a.Version, GroupIds = a.GroupIds.ToList() }).ToList(),
                State = _state.Values.Select(s => new
                { s.DeviceId, s.PackageId, s.InstalledVersion, s.Status, s.UpdatedUtc }).ToList(),
                PackRevisions = _packRevisions.Select(kv => new
                { PackId = kv.Key, Revision = kv.Value }).ToList(),
            });
            return Acp.Shared.Hub.HubPersistence.Wrap("acp-software-deployment-state-v1", payload);
        }
    }

    /// <summary>Restore state exported by ExportStateJson. Returns
    /// the number of entries restored (assignments + device states
    /// + pack revisions); 0 on any integrity/parse failure, in
    /// which case nothing is imported.</summary>
    public int ImportStateJson(string json)
    {
        var payload = Acp.Shared.Hub.HubPersistence.Unwrap(json, "acp-software-deployment-state-v1");
        if (payload is null) return 0;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(payload);
            var root = doc.RootElement;
            // BD-WIN-CORE-4/F7: parse EVERYTHING into local
            // collections first. The old shape mutated _assignments
            // / _state inside the loop, so a throw mid-file returned
            // 0 ("nothing imported") over a half-replaced state that
            // the downgrade + uninstall-forgery gates then read.
            var assignments = new List<DeploymentAssignment>();
            foreach (var a in root.GetProperty("Assignments").EnumerateArray())
            {
                var packageId = a.GetProperty("PackageId").GetString() ?? "";
                var version = a.GetProperty("Version").GetString() ?? "";
                var groups = a.GetProperty("GroupIds").EnumerateArray()
                    .Select(g => g.GetString() ?? "").ToList();
                assignments.Add(new DeploymentAssignment(packageId, version, groups));
            }
            var states = new List<DevicePackageState>();
            foreach (var s in root.GetProperty("State").EnumerateArray())
            {
                var status = s.GetProperty("Status").GetString() ?? "";
                if (status is not (DevicePackageState.Deployed or
                                   DevicePackageState.Uninstalled or
                                   DevicePackageState.PartiallyDeployed))
                    continue;
                states.Add(new DevicePackageState(
                    s.GetProperty("DeviceId").GetString() ?? "",
                    s.GetProperty("PackageId").GetString() ?? "",
                    s.GetProperty("InstalledVersion").GetString() ?? "",
                    status,
                    s.GetProperty("UpdatedUtc").GetDateTimeOffset()));
            }
            var revisions = new List<(string PackId, long Revision)>();
            foreach (var r in root.GetProperty("PackRevisions").EnumerateArray())
                revisions.Add((r.GetProperty("PackId").GetString() ?? "",
                    r.GetProperty("Revision").GetInt64()));
            // Every element parsed — apply in one step under the lock.
            var restored = 0;
            lock (_lock)
            {
                foreach (var assignment in assignments)
                {
                    _assignments.RemoveAll(x =>
                        string.Equals(x.PackageId, assignment.PackageId, StringComparison.OrdinalIgnoreCase));
                    _assignments.Add(assignment);
                    restored++;
                }
                foreach (var state in states)
                {
                    _state[StateKey(state.DeviceId, state.PackageId)] = state;
                    restored++;
                }
                foreach (var (packId, revision) in revisions)
                {
                    _packRevisions[packId] = revision;
                    restored++;
                }
            }
            return restored;
        }
        catch { return 0; }
    }

    // ---- convergence ----------------------------------------------------

    /// <summary>Convergence for one device against its assignments:
    /// desired (assigned) packages vs deployment records vs the
    /// RMM-04 observed software list the caller supplies.</summary>
    public IReadOnlyList<ConvergenceLine> ConvergenceFor(string deviceId,
        IReadOnlyList<SoftwareItem> observed)
    {
        var lines = new List<ConvergenceLine>();
        List<DeploymentAssignment> assignments;
        lock (_lock) assignments = _assignments.ToList();
        foreach (var a in assignments)
        {
            var package = _repository.Get(a.PackageId, a.Version);
            if (package is null) continue;
            lines.Add(DeploymentConvergence.Evaluate(package, StateFor(deviceId, a.PackageId),
                observed, deviceId));
        }
        return lines;
    }
}
