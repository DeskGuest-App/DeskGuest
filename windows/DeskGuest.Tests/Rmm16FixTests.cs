using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Deployment;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-16 D38 FIX lane — regression tests for the 12 findings of
// packet 358bc263 (verdict FAIL). Each test names its finding and
// attacks the PRODUCTION path the finding cited (signed delivery,
// the service, the runner as the service calls it) — not a
// repository-direct shortcut around it.
public class Rmm16FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string Group = "grp-bas";

    private static Rmm16Tests.Rig NewRig() => new();

    /// <summary>Replace the first manifest sha256 in a canonical
    /// JSON document with zeros — the embedded manifest now
    /// disagrees with the components it binds.</summary>
    private static string TamperFirstManifestSha(string json)
    {
        const string marker = "\"sha256\":\"";
        var idx = json.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(idx >= 0, "canonical JSON carries a manifest");
        var start = idx + marker.Length;
        return json[..start] + new string('0', 64) + json[(start + 64)..];
    }

    private static (DeploymentRunner Runner, string DeploymentId) RunnerFor(Rmm16Tests.Rig rig) =>
        (new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault), Guid.NewGuid().ToString("N"));

    private static SignedCommandEnvelope DeployEnvelope(Rmm16Tests.Rig rig, DeploymentPackage pkg,
        string deploymentId, string action = DeploymentActions.Deploy) =>
        rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev, action, false)),
            T0, TimeSpan.FromMinutes(5));

    private static SignedCommandEnvelope AutomationEnvelope(Rmm16Tests.Rig rig, DeploymentPackage pkg,
        string deploymentId, string action = DeploymentActions.Deploy)
    {
        var def = DeploymentBinding.DefinitionFor(pkg, action);
        var lib = DeploymentBinding.ExecutionLibrary(pkg, action);
        return rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, deploymentId,
                DeploymentBinding.AlertConditionId)),
            T0, TimeSpan.FromMinutes(5));
    }

    // ---- F1: the signed path must check the EMBEDDED manifest ----

    [Fact]
    public void F1_SignedPackage_EmbeddedManifestDisagrees_RefusedAtAdmission()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg();
        // The signer signs a package whose embedded manifest lies
        // about its components. The envelope signature is genuine —
        // the manifest binding is the check that must catch it.
        var tamperedJson = TamperFirstManifestSha(pkg.ToCanonicalJson());
        Assert.NotEqual(pkg.ToCanonicalJson(), tamperedJson);
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(tamperedJson), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedPackage(env);
        Assert.False(verdict.Allowed);
        Assert.Contains("manifest", verdict.Reason);
        Assert.Equal(0, rig.Repository.Count);
    }

    [Fact]
    public void F1_SignedContentPack_EmbeddedManifestDisagrees_RefusedWhole()
    {
        var rig = NewRig();
        var pack = new ContentPack("f1-pack", 1, new[]
        {
            Rmm16Tests.Pkg(id: "pack-a", version: "1.0.0"),
            Rmm16Tests.Pkg(id: "pack-b", version: "1.0.0"),
        });
        var tamperedJson = TamperFirstManifestSha(pack.ToCanonicalJson());
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(tamperedJson), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedContentPack(env);
        Assert.False(verdict.Allowed);
        Assert.Equal(0, rig.Repository.Count); // whole-pack: nothing admitted
    }

    // ---- F2: deploy time verifies against the ADMITTED anchors ----

    [Fact]
    public void F2_Runner_PackageMutatedAfterAdmission_RefusedByCarriedManifest()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var admitted = rig.Repository.Get("widget", "2.0.0")!;
        // Simulate the tampered-repository window: the object the
        // runner is handed has a swapped install step, genuinely
        // signed envelopes and all.
        var mutated = admitted with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: "evil")),
        };
        var (runner, deploymentId) = RunnerFor(rig);
        var exec = runner.Run(mutated, Dev, DeploymentActions.Deploy, false,
            DeployEnvelope(rig, mutated, deploymentId), AutomationEnvelope(rig, mutated, deploymentId),
            null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void F2_Runner_PackageMutatedAfterAdmission_RefusedByAdmittedHash()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var admitted = rig.Repository.Get("widget", "2.0.0")!;
        // Mutate a NON-step field and re-stamp the carried manifest
        // to match, so only the admitted-hash anchor can catch it.
        var mutated = admitted with { Description = "tampered description" };
        mutated = mutated with { CarriedManifest = mutated.Manifest() };
        var (runner, deploymentId) = RunnerFor(rig);
        var exec = runner.Run(mutated, Dev, DeploymentActions.Deploy, false,
            DeployEnvelope(rig, mutated, deploymentId), AutomationEnvelope(rig, mutated, deploymentId),
            null, null, () => true, null, null, deploymentId, T0,
            expectedContentHash: rig.Repository.AdmittedContentHash("widget", "2.0.0"));
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void F2_Runner_FilePackage_NoContentStore_RefusedNotFailOpen()
    {
        var rig = NewRig();
        var payload = Encoding.UTF8.GetBytes("widget-installer-bytes");
        var manifest = ContentManifest.Build(payload);
        var pkg = Rmm16Tests.Pkg() with
        {
            Files = new[] { new PackageFileComponent("f.bin", manifest.ContentHash, payload.Length, @"C:\Temp\f.bin") },
        };
        rig.AdmitAndAssign(pkg);
        var admitted = rig.Repository.Get("widget", "2.0.0")!;
        var (runner, deploymentId) = RunnerFor(rig);
        // Direct runner call with NO content store: the old code
        // skipped the file check entirely and executed.
        var exec = runner.Run(admitted, Dev, DeploymentActions.Deploy, false,
            DeployEnvelope(rig, admitted, deploymentId), AutomationEnvelope(rig, admitted, deploymentId),
            null, null, () => true, null, null, deploymentId, T0);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- F3: the stored package cannot be mutated through a read ----

    [Fact]
    public void F3_Get_ReturnedPackage_CastMutation_DoesNotReachTheStore()
    {
        var rig = NewRig();
        rig.Repository.Admit(Rmm16Tests.Pkg());
        var admittedHash = rig.Repository.AdmittedContentHash("widget", "2.0.0");
        var got = rig.Repository.Get("widget", "2.0.0")!;
        // The old Get handed out the stored object: casting its
        // IReadOnlyList fields back to List<T> rewrote the admitted
        // package in place.
        ((List<RemediationStep>)got.Install.Steps).Add(
            RemediationStep.Create("smuggled", RemediationStepKinds.RunScript, scriptBody: "evil"));
        ((List<RemediationStep>)got.Install.Steps)[0] =
            RemediationStep.Create("pre", RemediationStepKinds.RunScript, scriptBody: "evil");
        var again = rig.Repository.Get("widget", "2.0.0")!;
        Assert.Equal(2, again.Install.Steps.Count);
        Assert.DoesNotContain(again.Install.Steps, s => s.ScriptBody == "evil");
        Assert.Equal(admittedHash, again.ContentHash);
        // All and Latest hand out copies too.
        var fromAll = rig.Repository.All.Single();
        ((List<RemediationStep>)fromAll.Install.Steps).Clear();
        Assert.Equal(2, rig.Repository.Get("widget", "2.0.0")!.Install.Steps.Count);
    }

    // ---- F4: uninstall is not blocked by deploy-side gates ----

    [Fact]
    public void F4_Uninstall_RevokedPackage_Succeeds()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        rig.Repository.Revoke("widget", "2.0.0");
        // Deploy of the revoked package still refuses…
        Assert.False(rig.Service.Deploy("widget", "2.0.0", Dev, T0.AddMinutes(1)).Dispatched);
        // …but pulling it OFF the device — the operator's reason to
        // revoke — must work.
        var result = rig.Service.Uninstall("widget", Dev, T0.AddMinutes(2));
        Assert.True(result.Dispatched, result.Outcome);
        Assert.Equal(DevicePackageState.Uninstalled, rig.Service.StateFor(Dev, "widget")!.Status);
    }

    [Fact]
    public void F4_Uninstall_PerPackagePolicyDisabled_Succeeds()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        rig.SetPolicy(DeploymentPolicyKeys.PackageEnabled("widget"), "false", "off-widget");
        Assert.False(rig.Service.Deploy("widget", "2.0.0", Dev, T0.AddMinutes(1)).Dispatched);
        Assert.True(rig.Service.Uninstall("widget", Dev, T0.AddMinutes(2)).Dispatched);
    }

    [Fact]
    public void F4_Uninstall_AssignmentRetargetedAway_Succeeds()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        // Retarget the package to another group: this device is no
        // longer in the target set, so deploy refuses — uninstall
        // must not.
        rig.Service.Assign("widget", "2.0.0", new[] { "grp-other" }, "test-admin");
        Assert.False(rig.Service.Deploy("widget", "2.0.0", Dev, T0.AddMinutes(1)).Dispatched);
        Assert.True(rig.Service.Uninstall("widget", Dev, T0.AddMinutes(2)).Dispatched);
    }

    // ---- F5: a deployment whose steps ran is recorded ----

    [Fact]
    public void F5_PartialFailure_RecordsPartialState_UninstallAllowed_DowngradeSeesIt()
    {
        var rig = NewRig();
        var pkg = Rmm16Tests.Pkg() with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("s1", RemediationStepKinds.RunScript, scriptBody: "one"),
                RemediationStep.Create("s2", RemediationStepKinds.RunScript, scriptBody: "two")),
        };
        rig.AdmitAndAssign(pkg);
        rig.Executor.Results["s2"] = StepRunResult.Failure("installer died halfway");
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        // s1 ran: the device changed, and the record says so.
        var state = rig.Service.StateFor(Dev, "widget");
        Assert.NotNull(state);
        Assert.Equal(DevicePackageState.PartiallyDeployed, state!.Status);
        Assert.Equal("2.0.0", state.InstalledVersion);
        // Uninstall is not refused as a forgery.
        rig.Executor.Results.Remove("s2");
        Assert.True(rig.Service.Uninstall("widget", Dev, T0.AddMinutes(1)).Dispatched);
    }

    [Fact]
    public void F5_PartialState_BlocksSilentDowngrade()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "1.0.0"));
        var pkg2 = Rmm16Tests.Pkg(version: "2.0.0") with
        {
            Install = Rmm16Tests.Def("widget-install-2.0.0",
                RemediationStep.Create("s1", RemediationStepKinds.RunScript, scriptBody: "one"),
                RemediationStep.Create("s2", RemediationStepKinds.RunScript, scriptBody: "two")),
        };
        rig.AdmitAndAssign(pkg2);
        rig.Executor.Results["s2"] = StepRunResult.Failure("half-installed");
        Assert.False(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        Assert.Equal(DevicePackageState.PartiallyDeployed, rig.Service.StateFor(Dev, "widget")!.Status);
        // 2.0.0 is (partially) on the device: 1.0.0 over it is a
        // downgrade and needs the named decision.
        rig.Executor.Results.Remove("s2");
        rig.Service.Assign("widget", "1.0.0", new[] { Group }, "test-admin");
        var refused = rig.Service.Deploy("widget", "1.0.0", Dev, T0.AddMinutes(1));
        Assert.False(refused.Dispatched);
        Assert.Contains("downgrade", refused.Outcome);
    }

    // ---- F6: recorded state survives a hub restart (export/import) ----

    [Fact]
    public void F6_StateExportImport_DowngradeAndUninstallSurviveRestart()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "1.0.0"));
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "2.0.0"));
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        var exported = rig.Service.ExportStateJson();

        // A fresh service over the same hub stores = a hub restart.
        var svc2 = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, rig.Executor, null, () => rig.Now);
        svc2.InstalledVersionProbe = rig.ProbeInstalled;
        Assert.True(svc2.ImportStateJson(exported) > 0);
        Assert.Equal("2.0.0", svc2.StateFor(Dev, "widget")!.InstalledVersion);
        // The downgrade rule still sees the installed 2.0.0.
        svc2.Assign("widget", "1.0.0", new[] { Group }, "test-admin");
        var refused = svc2.Deploy("widget", "1.0.0", Dev, T0.AddMinutes(1));
        Assert.False(refused.Dispatched);
        Assert.Contains("downgrade", refused.Outcome);
        // And uninstall is not refused as a forgery.
        Assert.True(svc2.Uninstall("widget", Dev, T0.AddMinutes(2)).Dispatched);
        // A tampered export imports nothing.
        var svc3 = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, rig.Executor, null, () => rig.Now);
        Assert.Equal(0, svc3.ImportStateJson(exported.Replace("widget", "widgeu")));
        Assert.Null(svc3.StateFor(Dev, "widget"));
    }

    // ---- F7: licence values echoed by an installer are scrubbed ----

    [Fact]
    public void F7_ExecutorEchoingLicenceValue_ScrubbedBeforeEngineRecords()
    {
        const string echoValue = "XKCD-4821-9931";
        var rig = NewRig();
        var hash = rig.Vault.Store("echo-licence", echoValue);
        var pkg = new DeploymentPackage("echo-suite", "1.0.0", "Echo Suite", "", true, "Echo Suite",
            Array.Empty<PackageFileComponent>(),
            new[] { new PackageLicenceComponent("echo-licence", hash) },
            Rmm16Tests.Def("echo-suite-install",
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "setup.exe /licence {licence:echo-licence}")),
            Rmm16Tests.Def("echo-suite-uninstall",
                RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "Echo Suite")));
        var probe = new Rmm16Tests.ProbeExecutor(rig.Executor);
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, probe, null, () => rig.Now);
        svc.InstalledVersionProbe = rig.ProbeInstalled;
        Assert.True(svc.AdmitLocalPackage(pkg, "test").Allowed);
        svc.Assign("echo-suite", "1.0.0", new[] { Group }, "test-admin");
        // The installer echoes the materialised command line in its
        // error — the classic leak path into RMM-08 records/audit.
        rig.Executor.Results["install"] = StepRunResult.Failure($"invalid licence {echoValue}");
        var result = svc.Deploy("echo-suite", "1.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        // Sanity: the value genuinely reached the executor.
        Assert.Contains(echoValue, probe.LastScriptBody);
        // …and appears in NO recorded surface, audit included.
        var auditText = string.Join("\n", rig.Audit.Entries.Select(e => $"{e.Kind}|{e.Actor}|{e.Detail}"));
        Assert.DoesNotContain(echoValue, auditText);
        Assert.Contains("[licence value redacted]", auditText);
        Assert.DoesNotContain(echoValue, System.Text.Json.JsonSerializer.Serialize(svc.Executions));
    }

    // ---- F8: pack admission is atomic, cap included ----

    [Fact]
    public void F8_PackThatWouldBreachRepositoryCap_RefusedWhole_NothingAdmitted()
    {
        var rig = NewRig();
        for (var i = 0; i < PackageLimits.MaxPackagesPerRepository - 1; i++)
            Assert.True(rig.Repository.Admit(Rmm16Tests.Pkg(id: $"filler-{i}", version: "1.0.0")).Admitted);
        Assert.Equal(PackageLimits.MaxPackagesPerRepository - 1, rig.Repository.Count);
        // A 2-package pack needs 2 slots; only 1 remains. The old
        // per-package loop admitted the first, then refused at the
        // cap — a "refused" pack, half inside the repository.
        var pack = new ContentPack("cap-pack", 1, new[]
        {
            Rmm16Tests.Pkg(id: "cap-a", version: "1.0.0"),
            Rmm16Tests.Pkg(id: "cap-b", version: "1.0.0"),
        });
        var verdict = rig.Service.AdmitLocalContentPack(pack, "test");
        Assert.False(verdict.Allowed);
        Assert.Equal(PackageLimits.MaxPackagesPerRepository - 1, rig.Repository.Count);
        Assert.Null(rig.Repository.Get("cap-a", "1.0.0"));
        Assert.Null(rig.Repository.Get("cap-b", "1.0.0"));
    }

    // ---- F9: targeting ----

    [Fact]
    public void F9_Targets_UndefinedDirectGroupId_DoesNotTarget()
    {
        var rig = NewRig();
        // The device claims direct membership of a group that no
        // GroupDefinition defines. The old Targets() accepted any
        // claimed id; an assignment to that id must not target.
        var ghostFacts = StaticDeviceFacts.Of("dev-g", Scope, groups: new[] { "grp-ghost" });
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == "dev-g" ? ghostFacts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, rig.Executor, null, () => rig.Now);
        Assert.True(svc.AdmitLocalPackage(Rmm16Tests.Pkg(), "test").Allowed);
        svc.Assign("widget", "2.0.0", new[] { "grp-ghost" }, "test-admin");
        var result = svc.Deploy("widget", "2.0.0", "dev-g", T0);
        Assert.False(result.Dispatched);
        Assert.Contains("target set", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void F9_Assign_PackageIdCaseDiffers_StillTargets()
    {
        var rig = NewRig();
        Assert.True(rig.Service.AdmitLocalPackage(Rmm16Tests.Pkg(), "test").Allowed);
        // The repository and state stores ignore case; the old
        // ordinal assignment match made this silently target nothing.
        rig.Service.Assign("WIDGET", "2.0.0", new[] { Group }, "test-admin");
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
    }

    // ---- F10: one desired version per package ----

    [Fact]
    public void F10_AssignNewVersion_SupersedesOld_OldNotDeployable_ConvergenceSingleLine()
    {
        var rig = NewRig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "1.0.0"));
        Assert.True(rig.Service.Deploy("widget", "1.0.0", Dev, T0).Dispatched);
        rig.AdmitAndAssign(Rmm16Tests.Pkg(version: "2.0.0"));
        // 1.0.0 is no longer the desired version: it is not
        // targeted any more (the old pile-up left it deployable).
        var refused = rig.Service.Deploy("widget", "1.0.0", Dev, T0.AddMinutes(1));
        Assert.False(refused.Dispatched);
        Assert.Contains("target set", refused.Outcome);
        // Convergence speaks once per package, not contradictorily.
        var observed = new[] { new SoftwareItem("Widget", "1.0.0", null, null, null) };
        var line = Assert.Single(rig.Service.ConvergenceFor(Dev, observed));
        Assert.Equal("2.0.0", line.DesiredVersion);
        Assert.Equal(ConvergenceStates.Drifted, line.State);
    }

    // ---- F11: starter packs pin versions; convergence compares sanely ----

    [Fact]
    public void F11_StarterPacks_InstallCommandsPinTheDeclaredVersion()
    {
        foreach (var pack in new[] { StarterContentPacks.RuntimePack(), StarterContentPacks.UtilitiesPack() })
        foreach (var pkg in pack.Packages)
        {
            var bodies = string.Join("\n", pkg.Install.Steps.Select(s => s.ScriptBody ?? ""));
            Assert.Contains($"--version {pkg.Version}", bodies);
        }
        var vcredist = StarterContentPacks.RuntimePack().Packages.Single(p => p.Id == "vcredist-x64");
        Assert.Equal("Microsoft Visual C++ 2015-2022 Redistributable (x64)", vcredist.InstalledSoftwareName);
    }

    [Fact]
    public void F11_Convergence_ArpSuffixedNameAndShortVersion_CompliantNotDrifted()
    {
        var vcredist = StarterContentPacks.RuntimePack().Packages.Single(p => p.Id == "vcredist-x64");
        var recorded = new DevicePackageState(Dev, "vcredist-x64", "14.40.33810.0", DevicePackageState.Deployed, T0);
        // The real ARP entry carries " - <build>" on the NAME, and
        // its DisplayVersion may drop the trailing zero component.
        var observed = new[]
        {
            new SoftwareItem("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810.0",
                "14.40.33810", null, null, null),
        };
        var line = DeploymentConvergence.Evaluate(vcredist, recorded, observed, Dev);
        Assert.Equal(ConvergenceStates.Compliant, line.State);

        // "8.0" observed vs "8.0.0" recorded is the same version.
        var dotnet = StarterContentPacks.RuntimePack().Packages.Single(p => p.Id == "dotnet-desktop-runtime");
        var recorded8 = new DevicePackageState(Dev, "dotnet-desktop-runtime", "8.0.0", DevicePackageState.Deployed, T0);
        var observed8 = new[] { new SoftwareItem(".NET Desktop Runtime 8", "8.0", null, null, null) };
        var line8 = DeploymentConvergence.Evaluate(dotnet, recorded8, observed8, Dev);
        Assert.Equal(ConvergenceStates.Compliant, line8.State);
    }

    // ---- F12: placeholder casing + bounded execution history ----

    [Fact]
    public void F12_CaseVariantLicencePlaceholder_SubstitutedNotLiteral()
    {
        var rig = NewRig();
        var hash = rig.Vault.Store("suite-licence", Rmm16Tests.LicenceValue);
        var pkg = new DeploymentPackage("case-suite", "1.0.0", "Case Suite", "", true, "Case Suite",
            Array.Empty<PackageFileComponent>(),
            new[] { new PackageLicenceComponent("suite-licence", hash) },
            Rmm16Tests.Def("case-suite-install",
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "setup.exe /licence {licence:SUITE-LICENCE}")),
            Rmm16Tests.Def("case-suite-uninstall",
                RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "Case Suite")));
        var probe = new Rmm16Tests.ProbeExecutor(rig.Executor);
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, probe, null, () => rig.Now);
        svc.InstalledVersionProbe = rig.ProbeInstalled;
        Assert.True(svc.AdmitLocalPackage(pkg, "test").Allowed);
        svc.Assign("case-suite", "1.0.0", new[] { Group }, "test-admin");
        Assert.True(svc.Deploy("case-suite", "1.0.0", Dev, T0).Dispatched);
        // The executor received the VALUE, not the literal
        // case-variant placeholder.
        Assert.Contains(Rmm16Tests.LicenceValue, probe.LastScriptBody);
        Assert.Equal(-1, (probe.LastScriptBody ?? "").IndexOf("{licence:", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void F12_UpperCasePlaceholderForUnboundKey_RefusedAtAdmission()
    {
        var rig = NewRig();
        var pkg = new DeploymentPackage("shouty", "1.0.0", "Shouty", "", true, null,
            Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
            Rmm16Tests.Def("shouty-install",
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "setup /licence {LICENCE:ghost-key}")),
            Rmm16Tests.Def("shouty-uninstall",
                RemediationStep.Create("u", RemediationStepKinds.UninstallApp, target: "X")));
        // The old case-sensitive scan never saw "{LICENCE:" and
        // admitted a step reaching for an unbound key.
        var (ok, reason) = rig.Repository.Admit(pkg);
        Assert.False(ok);
        Assert.Contains("does not bind", reason);
    }

    [Fact]
    public void F12_ExecutionHistory_IsBounded()
    {
        var rig = NewRig();
        // Distinct packages per deployment, so the count measures
        // only the history bound, nothing per-definition.
        for (var i = 0; i < SoftwareDeploymentService.MaxRetainedExecutions + 4; i++)
        {
            var id = $"bound-{i}";
            rig.AdmitAndAssign(Rmm16Tests.Pkg(id: id, version: "1.0.0"));
            Assert.True(rig.Service.Deploy(id, "1.0.0", Dev, T0.AddMinutes(i)).Dispatched);
        }
        Assert.Equal(SoftwareDeploymentService.MaxRetainedExecutions, rig.Service.Executions.Count);
    }
}
