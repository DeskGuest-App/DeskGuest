using System.Text;
using Acp.Shared.Audit;
using Acp.Shared.Distribution;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Shared.Deployment;

// =====================================================================
// RMM-16 — the deployment half: policy targeting, the signed
// deployment binding, the endpoint-side runner, and convergence
// against RMM-04 inventory.
//
//   * NOTHING deploys before the RMM-03 gate verifies the
//     deployment's `package_deploy` envelope, and the envelope's
//     payload must bind THIS package (id + version + content hash),
//     THIS device, THIS action (deploy/uninstall) and the
//     downgrade decision bit. An envelope minted for a deploy never
//     authorises an uninstall; one minted for another device or
//     package version executes nothing here.
//   * The package is RE-VERIFIED at deploy time: shape, manifest
//     recomputation, vault-hash agreement, revocation, and every
//     file component's bytes (via the RMM-14 store/manifest) must
//     still agree with what was signed. Admission-time checks do
//     not substitute for deploy-time checks — the repository could
//     have been tampered with in between, and that is exactly the
//     window this closes.
//   * Execution consumes RMM-08: the package's install/uninstall
//     AutomationDefinition runs through RemediationRunner (its own
//     `automation` envelope, its own gate verification, bounded
//     steps, redacted bounded output). Licence keys are revealed
//     from the vault ONLY into LicenceSubstitutingExecutor, which
//     replaces {licence:<ref>} placeholders in step fields at the
//     moment a step executes — the definition the engine verifies
//     and hash-binds is the TEMPLATE form, so no key value ever
//     enters a hash, a record, or the audit chain.
//   * The whole deployment is checkpointed as an RMM-15
//     JobKinds.Deployment job (fetch → verify → execute →
//     verify_install), so a deployment interrupted by reboot or
//     disconnect resumes under the journal's discipline; the
//     non-idempotent execute step parks rather than guesses.
//   * Downgrade discipline: deploying a version OLDER than the
//     version recorded installed on the device refuses unless the
//     signed binding carries an explicit downgrade decision (the
//     service mints that bit only for a named human decision, and
//     the runner re-checks it independently).
// =====================================================================

public static class DeploymentActions
{
    public const string Deploy = "deploy";
    public const string Uninstall = "uninstall";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Deploy, Uninstall };
}

public static class DeploymentOutcomes
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string PartialFailure = "partial_failure";
    public const string Refused = "refused";
}

/// <summary>The signed payload binding for one deployment. The
/// package_deploy envelope's payload must equal this string
/// exactly.</summary>
public static class DeploymentBinding
{
    /// <summary>The condition id the runner's synthetic alert
    /// carries. The RMM-08 binding (D38-F1/F12, payload v2) binds
    /// the alert's condition into the automation envelope, so the
    /// hub service must mint with THIS condition id — when it
    /// omitted it, every deployment execution was refused on
    /// binding mismatch. One definition, both sides.</summary>
    public const string AlertConditionId = "package_deployment";

    public static string Payload(DeploymentPackage package, string deviceId, string action,
        bool downgradeApproved) =>
        $"package_deploy|{package.Id}|{package.Version}|{package.ContentHash}|{deviceId}|{action}|{(downgradeApproved ? "downgrade-approved" : "standard")}";

    /// <summary>The synthetic single-definition library an install/
    /// uninstall execution runs under (the RemediationRunner's
    /// library parameter): the package IS the library for its own
    /// execution, revision = the package's content identity.</summary>
    public static AutomationLibrary ExecutionLibrary(DeploymentPackage package, string action)
    {
        var def = action == DeploymentActions.Uninstall ? package.Uninstall : package.Install;
        return new AutomationLibrary($"pkg:{package.Id}@{package.Version}", 1, new[] { def });
    }

    public static AutomationDefinition DefinitionFor(DeploymentPackage package, string action) =>
        action == DeploymentActions.Uninstall ? package.Uninstall : package.Install;
}

/// <summary>The RMM-15 Deployment job's step list, with honest
/// idempotency marks: fetch/verify are content-addressed pure
/// checks (safe to repeat); execute runs installers (an interrupted
/// execute leaves genuinely unknown state — the journal PARKS it);
/// verify_install re-reads installed state (safe).</summary>
public static class DeploymentJobSteps
{
    public const string Fetch = "fetch_payloads";
    public const string Verify = "verify_package";
    public const string Execute = "execute_definition";
    public const string VerifyInstall = "verify_install";

    public static IReadOnlyList<JobStepDefinition> For(string action) => new[]
    {
        new JobStepDefinition(Fetch, "Fetch package payloads (RMM-14)", StepIdempotency.Idempotent),
        new JobStepDefinition(Verify, "Verify package manifest + components", StepIdempotency.Idempotent),
        new JobStepDefinition(Execute, action == DeploymentActions.Uninstall ? "Execute uninstall definition" : "Execute install definition", StepIdempotency.NonIdempotent),
        new JobStepDefinition(VerifyInstall, "Verify resulting installed state", StepIdempotency.Idempotent),
    };
}

/// <summary>The step executor wrapper that is the licence keys'
/// ONLY destination. It wraps the host's real executor: before a
/// step runs, {licence:&lt;ref&gt;} placeholders in its fields are
/// replaced with the values revealed for THIS execution. The
/// wrapped executor therefore sees real keys in its step input
/// (its execution context); the engine, the journal, the audit
/// chain and every record keep the template form. Revealed values
/// are held in memory for one run and never written anywhere by
/// this class.</summary>
public sealed class LicenceSubstitutingExecutor : IRemediationStepExecutor, IPatchRerunTarget
{
    private readonly IRemediationStepExecutor _inner;
    private readonly IReadOnlyDictionary<string, string> _revealed;

    public LicenceSubstitutingExecutor(IRemediationStepExecutor inner,
        IReadOnlyDictionary<string, string> revealed)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _revealed = revealed ?? throw new ArgumentNullException(nameof(revealed));
    }

    /// <summary>Refs revealed into this execution (refs, never
    /// values — safe to record).</summary>
    public IReadOnlyList<string> RevealedRefs => _revealed.Keys.OrderBy(r => r, StringComparer.Ordinal).ToList();

    private string? Substitute(string? field)
    {
        if (field is null) return null;
        var result = field;
        foreach (var (reference, value) in _revealed)
            // D38-F12a: case-INSENSITIVE, matching admission's
            // case-insensitive placeholder scan — a step written
            // {licence:Suite-Licence} must not reach the installer
            // with the literal placeholder still in it.
            result = result.Replace(PackageHashing.LicencePlaceholder(reference), value, StringComparison.OrdinalIgnoreCase);
        return result;
    }

    /// <summary>D38-F7: scrub revealed licence VALUES out of the
    /// inner executor's result before it reaches the RMM-08 engine.
    /// An installer that echoes its command line (or reports
    /// "invalid licence XYZ") would otherwise carry the key into
    /// the engine's execution records — the engine's generic
    /// redactor cannot know these values; this wrapper does, so the
    /// scrub happens here, at the only place the values exist.</summary>
    private StepRunResult Scrub(StepRunResult result)
    {
        var output = result.Output ?? "";
        var error = result.Error;
        foreach (var value in _revealed.Values)
        {
            if (string.IsNullOrEmpty(value)) continue;
            output = output.Replace(value, "[licence value redacted]", StringComparison.Ordinal);
            error = error?.Replace(value, "[licence value redacted]", StringComparison.Ordinal);
        }
        return result with { Output = output, Error = error };
    }

    public StepRunResult Execute(RemediationStep step, RemediationExecutionContext context)
    {
        var materialized = step with
        {
            Target = Substitute(step.Target),
            Argument = Substitute(step.Argument),
            ScriptBody = Substitute(step.ScriptBody),
        };
        return Scrub(_inner.Execute(materialized, context));
    }

    public StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context) =>
        _inner is IPatchRerunTarget target
            ? Scrub(target.RerunPatch(patchEntryId, context))
            : StepRunResult.Failure("the wrapped executor offers no patch re-run target");
}

/// <summary>One deployment's full record: the package identity, the
/// action, the RMM-08 execution it ran as, and the RMM-15 job that
/// checkpointed it. Carries hashes and refs — never key values.</summary>
public sealed record DeploymentExecution(
    string DeploymentId,
    string PackageId,
    string PackageVersion,
    string PackageHash,
    string DeviceId,
    string Action,
    DateTimeOffset StartedUtc,
    string Outcome,
    string? JobId,
    string? RemediationExecutionId,
    IReadOnlyList<string> LicenceRefsRevealed,
    // D38-F5: true when the engine completed at least one step —
    // the device changed even if the deployment did not fully
    // succeed, and the hub must record that (see DevicePackageState).
    bool AnyStepExecuted = false);

/// <summary>Per-device deployment state the hub keeps: what version
/// of a package is recorded deployed where. This is the state the
/// downgrade rule and the uninstall-forgery rule read, and the
/// state convergence checks against RMM-04 inventory.</summary>
public sealed record DevicePackageState(
    string DeviceId, string PackageId, string InstalledVersion, string Status,
    DateTimeOffset UpdatedUtc)
{
    public const string Deployed = "deployed";
    public const string Uninstalled = "uninstalled";
    /// <summary>D38-F5: steps ran but the deployment did not fully
    /// succeed (partial failure, or a mid-flight abort after a step
    /// completed). The device HAS changed: this state keeps the
    /// package uninstallable and visible to the downgrade rule
    /// instead of the old behaviour — nothing recorded, uninstall
    /// refused as a forgery, downgrade check blind.</summary>
    public const string PartiallyDeployed = "partially_deployed";
}

/// <summary>A policy targeting assignment: this package version is
/// deployed to devices in these groups (static or dynamic — the
/// RMM-07 GroupDefinition membership test decides). A package with
/// NO assignment targets nothing: deployment by policy means an
/// unassigned package deploys nowhere, and a device outside the
/// assignment's groups is refused by name.</summary>
public sealed record DeploymentAssignment(
    string PackageId, string Version, IReadOnlyList<string> GroupIds)
{
    public bool Targets(IDeviceFacts facts, IReadOnlyList<GroupDefinition> groups)
    {
        var wanted = new HashSet<string>(GroupIds, StringComparer.OrdinalIgnoreCase);
        return groups.Any(g => wanted.Contains(g.Id) && g.IsMember(facts)) ||
               // D38-F9b: a direct group id only targets when that
               // group is actually DEFINED — the old branch accepted
               // any id the device claimed, defined or not.
               facts.DirectGroupIds.Any(id => wanted.Contains(id) &&
                   groups.Any(g => string.Equals(g.Id, id, StringComparison.OrdinalIgnoreCase)));
    }
}

public static class ConvergenceStates
{
    public const string Compliant = "compliant";     // installed at the desired version
    public const string Drifted = "drifted";         // installed at a different version
    public const string Missing = "missing";         // desired but not installed
    public const string Unmanaged = "unmanaged";     // installed, no deployment record (not ACP-deployed)
    /// <summary>bd-shared-plat-1/F1: recorded deployed but inventory
    /// cannot see it (removed outside ACP, or never landed) — drift
    /// by definition, never compliant.</summary>
    public const string RecordedNotObserved = "recorded_not_observed";
    /// <summary>bd-shared-plat-1/F1: the package names no
    /// InstalledSoftwareName, so inventory can never observe it —
    /// convergence is unobservable, never compliant.</summary>
    public const string Unobservable = "unobservable";
}

/// <summary>One device's convergence line for one package, computed
/// from the deployment record + RMM-04 inventory facts. Inventory
/// is the observed truth; the deployment record is the intent; a
/// disagreement is drift, named — never silently reconciled.</summary>
public sealed record ConvergenceLine(
    string DeviceId, string PackageId, string DesiredVersion,
    string? RecordedVersion, string? ObservedVersion, string State);

public static class DeploymentConvergence
{
    /// <summary>Evaluate one device. <paramref name="observed"/> is
    /// the device's RMM-04 software list; a package observes through
    /// its InstalledSoftwareName.</summary>
    public static ConvergenceLine Evaluate(DeploymentPackage desired, DevicePackageState? recorded,
        IReadOnlyList<SoftwareItem> observed, string deviceId)
    {
        string? observedVersion = null;
        if (desired.InstalledSoftwareName is not null)
        {
            var norm = InventoryValidation.NormalizeSoftwareName(desired.InstalledSoftwareName);
            // D38-F11: real Add/Remove Programs entries often carry
            // a " - <version>" suffix on the name itself (e.g. the
            // VC++ redistributable) — match the bare name or the
            // bare name + " - " prefix shape, nothing looser.
            observedVersion = observed.FirstOrDefault(s =>
                s.NormalizedName == norm ||
                s.NormalizedName.StartsWith(norm + " - ", StringComparison.OrdinalIgnoreCase))?.Version;
        }
        var recordedVersion = recorded is { Status: DevicePackageState.Deployed or DevicePackageState.PartiallyDeployed }
            ? recorded.InstalledVersion : null;
        string state;
        // bd-shared-plat-1/F1: recorded-but-not-observed is drift,
        // and a package with no inventory name is unobservable —
        // neither may fall through to Compliant.
        if (desired.InstalledSoftwareName is null && recordedVersion is not null)
            state = ConvergenceStates.Unobservable;
        else if (observedVersion is null && recordedVersion is not null)
            state = ConvergenceStates.RecordedNotObserved;
        else if (observedVersion is not null && recordedVersion is null) state = ConvergenceStates.Unmanaged;
        else if (observedVersion is null && recordedVersion is null) state = ConvergenceStates.Missing;
        else if (observedVersion is not null && recordedVersion is not null &&
                 // D38-F11: versions compare with SoftwareVersion
                 // semantics, not raw strings — "8.0" observed vs
                 // "8.0.0" recorded is the same version, not drift.
                 SoftwareVersion.Compare(observedVersion, recordedVersion) != 0)
            state = ConvergenceStates.Drifted; // the machine disagrees with the record
        else if (recordedVersion is not null &&
                 SoftwareVersion.Compare(recordedVersion, desired.Version) != 0)
            state = ConvergenceStates.Drifted; // deployed, but not at the desired version
        else state = ConvergenceStates.Compliant;
        return new ConvergenceLine(deviceId, desired.Id, desired.Version, recordedVersion, observedVersion, state);
    }
}

/// <summary>The endpoint-side deployment runner. One Run = one
/// deployment action: gate verification, deploy-time package
/// re-verification, payload fetch/verify, then the RMM-08 engine
/// executes the package's definition. Every refusal is a chained
/// audit event and executes nothing.</summary>
public sealed class DeploymentRunner
{
    private readonly IRemediationStepExecutor _executor;
    private readonly SignedCommandGate? _gate;
    private readonly ChainedAuditLog _audit;
    private readonly PackageSecretVault _vault;

    public DeploymentRunner(IRemediationStepExecutor executor, SignedCommandGate? gate,
        ChainedAuditLog audit, PackageSecretVault vault)
    {
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _gate = gate;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
    }

    /// <param name="envelope">The package_deploy envelope (the
    /// deployment's authority).</param>
    /// <param name="automationEnvelope">The inner automation
    /// envelope the RemediationRunner verifies.</param>
    /// <param name="journalEnvelope">The inner script_exec envelope
    /// the journal binds for the engine's script_chain job.</param>
    /// <param name="installedVersion">The version currently
    /// recorded installed on this device (null = none) — the
    /// downgrade rule's input, re-checked here independently of
    /// the service that minted the envelope.</param>
    /// <param name="contentStore">The endpoint's RMM-14 store: file
    /// components must be held, hash-verified, before execution.</param>
    /// <param name="deploymentId">The deployment's id, generated by
    /// the hub service: it is ALSO the inner execution's alert id,
    /// which is what lets the service mint the inner automation
    /// envelope's binding (def | library | device | alertId) before
    /// the run — the binding stays exact, never predicted.</param>
    public DeploymentExecution Run(
        DeploymentPackage package, string deviceId, string action, bool downgradeApproved,
        SignedCommandEnvelope? envelope, SignedCommandEnvelope? automationEnvelope,
        SignedCommandEnvelope? journalEnvelope,
        JobJournal? journal, Func<bool> policyStillEnabled,
        string? installedVersion, PeerContentStore? contentStore,
        string deploymentId, DateTimeOffset now,
        // D38-F2: the content hash recorded at ADMISSION (the
        // repository's anchor). When supplied, the package handed
        // to the runner must recompute to it — the old runner
        // verified the package only against itself, so a repository
        // tampered with between admission and deploy was signed
        // fresh and ran.
        string? expectedContentHash = null,
        // bd-shared-plat-1/F2: revocation is re-checked HERE, at
        // deploy time in the runner itself — not only by the hub
        // service that dispatched. A caller that wires the
        // repository predicate cannot run a revoked version even
        // if its own pre-checks were bypassed.
        Func<string, string, bool>? isRevoked = null,
        // bd-shared-plat-1/F4: post-install probe — returns the
        // version inventory NOW observes for this package (null =
        // not observed). When a journal is present, verify_install
        // completes ONLY when the probe observes the deployed
        // version (deploy) or observes nothing (uninstall). With
        // no probe wired the step FAILS rather than claiming a
        // verification that never happened.
        Func<DeploymentPackage, string?>? installedVersionProbe = null)
    {
        DeploymentExecution Finish(string outcome, string? jobId, string? execId,
            IReadOnlyList<string>? refs = null, bool anyStepExecuted = false) =>
            new(deploymentId, package.Id, package.Version, package.ContentHash, deviceId, action,
                now, outcome, jobId, execId, refs ?? Array.Empty<string>(), anyStepExecuted);

        DeploymentExecution Refuse(string reason)
        {
            _audit.Append("deployment_refused", "deployment-runner",
                $"deployment={deploymentId} package={package.Id} v{package.Version} device={deviceId} action={action} reason={reason}", now);
            return Finish(DeploymentOutcomes.Refused, null, null);
        }

        if (!DeploymentActions.All.Contains(action ?? ""))
            return Refuse($"unknown deployment action '{action}' — refused");
        if (!package.Enabled)
            return Refuse($"package '{package.Id}' v{package.Version} is disabled (a template or a policy-disabled package never deploys) — refused");
        // bd-shared-plat-1/F2: deploy-time revocation, in the runner.
        // Deploy only: revocation pulls a package from the field, it
        // must never block REMOVING that same package — an uninstall
        // of a revoked version is the remediation, not the threat
        // (D38-era contract: uninstall of a revoked package succeeds).
        if (action == DeploymentActions.Deploy && isRevoked is not null && isRevoked(package.Id, package.Version))
            return Refuse($"package '{package.Id}' v{package.Version} is revoked — refused at deploy time in the runner (a pulled package deploys nowhere, however valid its envelope)");

        // ---- RMM-03 gate: NOTHING deploys unverified. ----
        if (_gate is null)
            return Refuse("no signed-command gate wired on the agent — deployment refuses (RMM-03: unsigned commands never execute)");
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PackageDeploy);
        if (!verdict.Allowed) return Refuse(verdict.Reason);
        var expected = DeploymentBinding.Payload(package, deviceId, action, downgradeApproved);
        var actual = Encoding.UTF8.GetString(verdict.Payload!);
        if (actual != expected)
            return Refuse("the signed envelope does not bind THIS package, version, content, device, action and downgrade bit (payload binding mismatch) — refused (an envelope minted for another package, device or action never executes this one)");

        // ---- Downgrade discipline, re-checked endpoint-side. ----
        if (action == DeploymentActions.Deploy && installedVersion is not null &&
            SoftwareVersion.Compare(package.Version, installedVersion) < 0 && !downgradeApproved)
            return Refuse($"downgrade refused: package '{package.Id}' v{package.Version} is older than the installed v{installedVersion} and the signed binding carries no downgrade decision — refused (an older signed version never silently replaces a newer install)");

        // ---- Deploy-time re-verification (the admission window). ----
        if (package.Validate() is { } invalidNow)
            return Refuse($"deploy-time verification failed: {invalidNow}");
        // D38-F2: verify against anchors recorded at ADMISSION, not
        // against the package itself: the carried (admitted)
        // manifest, and the admitted content hash when the caller
        // supplies it.
        if (package.CarriedManifest is not null &&
            package.VerifyManifest(package.CarriedManifest) is { } manifestMismatch)
            return Refuse($"deploy-time verification failed: {manifestMismatch}");
        if (expectedContentHash is not null &&
            !string.Equals(expectedContentHash, package.ContentHash, StringComparison.OrdinalIgnoreCase))
            return Refuse($"deploy-time verification failed: package '{package.Id}' v{package.Version} content hash does not match the hash recorded at admission — refused (the repository was tampered with between admission and deploy)");
        // bd-shared-plat-1/F9: with NEITHER anchor present the
        // package would be verified only against itself — fail
        // closed. (The hub service always passes the admission
        // hash; a carried manifest is the signed-delivery anchor.)
        if (expectedContentHash is null && package.CarriedManifest is null)
            return Refuse($"deploy-time verification failed: package '{package.Id}' v{package.Version} carries no admission anchor (no expected content hash and no carried manifest) — refused rather than verifying the package against itself");
        foreach (var lic in package.LicenceKeys)
        {
            var vaultHash = _vault.HashOf(lic.Ref);
            if (vaultHash is null || !string.Equals(vaultHash, lic.ValueHash, StringComparison.OrdinalIgnoreCase))
                return Refuse($"deploy-time verification failed: licence '{lic.Ref}' no longer agrees with the vault — refused (the key this package was signed for is not the key now held)");
        }
        // D38-F2: the file check no longer fails open — a DEPLOY
        // with file components and NO content store refuses (the
        // old `if (contentStore is not null)` skipped the check
        // entirely on a direct runner call). Uninstall does not
        // need the payloads and is not gated on the store.
        if (action == DeploymentActions.Deploy && package.Files.Count > 0 && contentStore is null)
            return Refuse($"deploy-time verification failed: package '{package.Id}' v{package.Version} carries {package.Files.Count} file component(s) but no content store was supplied — refused rather than deploying without its files");
        if (action == DeploymentActions.Deploy && contentStore is not null)
        {
            foreach (var file in package.Files)
                if (!contentStore.Has(file.ContentHash))
                    return Refuse($"deploy-time verification failed: file component '{file.Name}' (hash {file.ContentHash[..12]}…) is not held, hash-verified, in the content store — refused (payloads arrive via RMM-14 verified distribution or not at all)");
        }

        // ---- RMM-15 deployment job. ----
        ResumableJob? job = null;
        if (journal is not null)
        {
            job = journal.CreateJob(JobKinds.Deployment, deviceId,
                DeploymentJobSteps.For(action), envelope, now);
            if (job is null)
                return Refuse("the job journal refused the deployment job (envelope class/expiry or step shape) — deployment refuses rather than run uncheckpointed");
            journal.StartJob(job.Id, now);
            // Fetch + verify are complete by construction at this
            // point (verification above IS the verify step; payload
            // presence in the verified store IS the fetch result).
            foreach (var stepId in new[] { DeploymentJobSteps.Fetch, DeploymentJobSteps.Verify })
            {
                if (journal.BeginStep(job.Id, stepId, now)) journal.CompleteStep(job.Id, stepId, now);
            }
        }

        // ---- Licence reveal: into the execution context ONLY. ----
        var revealed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lic in package.LicenceKeys)
        {
            var value = _vault.Reveal(lic.Ref);
            if (value is null)
            {
                if (job is not null && journal!.BeginStep(job.Id, DeploymentJobSteps.Execute, now))
                    journal.FailStep(job.Id, DeploymentJobSteps.Execute, $"licence '{lic.Ref}' could not be revealed from the vault", now);
                return Refuse($"licence '{lic.Ref}' could not be revealed from the vault — refused (deployment never runs with a missing key substituted or skipped)");
            }
            revealed[lic.Ref] = value;
        }
        var executor = revealed.Count > 0
            ? (IRemediationStepExecutor)new LicenceSubstitutingExecutor(_executor, revealed)
            : _executor;

        // ---- Execution via the RMM-08 engine. ----
        var def = DeploymentBinding.DefinitionFor(package, action);
        var library = DeploymentBinding.ExecutionLibrary(package, action);
        var alert = new HealthAlertEvent(deploymentId, deviceId, DeploymentBinding.AlertConditionId,
            "deployment", AlertSeverities.Info, HealthAlertStates.Raised, now, now, 1,
            $"package {action}: {package.Id} v{package.Version}", null, null, null, null, "hub");
        var runner = new RemediationRunner(executor, _gate, _audit);
        if (job is not null) journal!.BeginStep(job.Id, DeploymentJobSteps.Execute, now);
        var execution = runner.Run(def, library, alert, automationEnvelope, journal, journalEnvelope,
            policyStillEnabled, now);

        if (execution.Outcome == RemediationOutcomes.Refused)
        {
            if (job is not null && !job.IsTerminal)
                journal!.FailStep(job.Id, DeploymentJobSteps.Execute, "the remediation engine refused the execution (see audit)", now);
            _audit.Append("deployment_refused", "deployment-runner",
                $"deployment={deploymentId} package={package.Id} v{package.Version} device={deviceId} action={action} reason=the RMM-08 engine refused the execution (envelope binding) — deployment did not run", now);
            return Finish(DeploymentOutcomes.Refused, job?.Id, execution.ExecutionId, revealed.Keys.ToList(),
                execution.Steps.Any(s => s.State == StepExecutionStates.Done));
        }

        var outcome = execution.Outcome switch
        {
            RemediationOutcomes.Succeeded => DeploymentOutcomes.Succeeded,
            RemediationOutcomes.PartialFailure => DeploymentOutcomes.PartialFailure,
            _ => DeploymentOutcomes.Failed,
        };
        if (job is not null && !job.IsTerminal)
        {
            if (outcome == DeploymentOutcomes.Succeeded)
            {
                journal!.CompleteStep(job.Id, DeploymentJobSteps.Execute, now);
                // bd-shared-plat-1/F4: verify_install must READ
                // installed state. No probe wired, or a probe that
                // does not observe the expected end state, FAILS
                // the step and downgrades the outcome — the journal
                // never records a verification that did not happen.
                string? verifyError;
                if (installedVersionProbe is null)
                    verifyError = "no post-install inventory probe is wired on this runner — verify_install cannot read installed state, so it does not claim verification";
                else
                {
                    string? observedNow;
                    try { observedNow = installedVersionProbe(package); }
                    catch (Exception ex) { observedNow = null; verifyError = $"post-install probe threw ({ex.GetType().Name}) — installed state unobserved"; goto VerifyDone; }
                    verifyError = action == DeploymentActions.Deploy
                        ? (observedNow is not null && SoftwareVersion.Compare(observedNow, package.Version) == 0
                            ? null
                            : $"post-install inventory does not observe '{package.Id}' at v{package.Version} (observed: {observedNow ?? "nothing"}) — install not verified")
                        : (observedNow is null
                            ? null
                            : $"post-uninstall inventory still observes '{package.Id}' at v{observedNow} — uninstall not verified");
                }
            VerifyDone:
                if (journal.BeginStep(job.Id, DeploymentJobSteps.VerifyInstall, now))
                {
                    if (verifyError is null) journal.CompleteStep(job.Id, DeploymentJobSteps.VerifyInstall, now);
                    else
                    {
                        journal.FailStep(job.Id, DeploymentJobSteps.VerifyInstall, verifyError, now);
                        outcome = DeploymentOutcomes.PartialFailure;
                        _audit.Append("deployment_verify_install_failed", "deployment-runner",
                            $"deployment={deploymentId} package={package.Id} v{package.Version} device={deviceId} action={action} reason={verifyError}", now);
                    }
                }
            }
            else
            {
                journal!.FailStep(job.Id, DeploymentJobSteps.Execute, $"execution outcome {execution.Outcome}", now);
            }
        }
        _audit.Append("deployment_completed", "deployment-runner",
            $"deployment={deploymentId} package={package.Id} v{package.Version} hash={package.ContentHash[..12]}… device={deviceId} action={action} outcome={outcome} job={job?.Id ?? "(none)"} execution={execution.ExecutionId} licencesRevealed={revealed.Count} (refs only; values never enter the audit chain)", now);
        return Finish(outcome, job?.Id, execution.ExecutionId, revealed.Keys.ToList(),
            execution.Steps.Any(s => s.State == StepExecutionStates.Done));
    }
}
