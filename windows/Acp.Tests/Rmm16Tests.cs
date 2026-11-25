using System.Text;
using Acp.Core.Services;
using Acp.Shared.Deployment;
using Acp.Shared.Distribution;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-16 — Software deployment: package repository + content packs.
// Repository admission (manifest hash-binding, vault discipline),
// policy targeting, signed deployment via the RMM-08 engine,
// RMM-14 payloads, RMM-15 deployment jobs, downgrade discipline,
// uninstall as a first-class path, convergence vs RMM-04, and the
// starter content packs. Executors are fakes; nothing installs
// real software.
public class Rmm16Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Group = "grp-bas";
    public const string LicenceValue = "ACME-LIC-9F27-44KD-SECRET-7712";

    // ---- fixtures ------------------------------------------------------

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { Group });
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope, groups: new[] { "grp-other" });
        public RecordingRemediationStepExecutor Executor = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public PackageSecretVault Vault = new(new DevOnlyPassThroughProtector());
        public PackageRepository Repository;
        public SoftwareDeploymentService Service;

        public Rig(bool signer = true, bool gate = true)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Repository = new PackageRepository(Vault);
            Policy.AddGroup(new GroupDefinition(Group, "BAS workstations", Array.Empty<GroupRule>()));
            Service = new SoftwareDeploymentService(Audit, Policy,
                id => id == Dev ? Facts : id == Dev2 ? Facts2 : null,
                signer ? Signer : null, gate ? Gate : null, Repository, Vault, Executor,
                null, () => Now);
            // bd-shared-plat-1/F4: the rig's simulated inventory
            // observes what the fake executor actually did — the
            // package's version after its install step ran, nothing
            // after its uninstall step ran. verify_install reads it.
            Service.InstalledVersionProbe = ProbeInstalled;
        }

        /// <summary>Simulated inventory for verify_install: derives
        /// the observed version from the executor's own call log, so
        /// a deployment whose install step never ran (or whose
        /// uninstall ran last) is observed honestly.</summary>
        public string? ProbeInstalled(DeploymentPackage pkg, string deviceId)
        {
            var last = Executor.Calls.LastOrDefault(c => c.StepId is "install" or "uninstall");
            return last.StepId == "install" ? pkg.Version : null;
        }

        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, 1));

        public DeploymentPackage AdmitAndAssign(DeploymentPackage pkg)
        {
            Assert.True(Service.AdmitLocalPackage(pkg, "test").Allowed);
            Service.Assign(pkg.Id, pkg.Version, new[] { Group }, "test-admin");
            return pkg;
        }
    }

    public static AutomationDefinition Def(string id, params RemediationStep[] steps) =>
        // RMM-08 D38-F11: definitions carrying high-impact kinds
        // (run_script / uninstall_app) are admissible only at the
        // requires_approval tier — package fixtures follow the same
        // admission discipline the probe enforces.
        AutomationDefinition.Create(id, id, steps, tier: RemediationTiers.RequiresApproval,
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    /// <summary>A plain package: one install script step, one
    /// uninstall step, no files, no licences.</summary>
    public static DeploymentPackage Pkg(string id = "widget", string version = "2.0.0", bool enabled = true) =>
        new(id, version, $"Widget {version}", "test package", enabled, "Widget",
            Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
            Def($"{id}-install-{version}",
                RemediationStep.Create("pre", RemediationStepKinds.Wait, argument: "0"),
                RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: $"install-widget {version}")),
            Def($"{id}-uninstall-{version}",
                RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "Widget")));

    /// <summary>A licence-bound package: the install script consumes
    /// the key through the {licence:…} placeholder.</summary>
    public static DeploymentPackage LicensedPkg(Rig rig, string id = "suite", string version = "1.0.0")
    {
        var hash = rig.Vault.Store("suite-licence", LicenceValue);
        return new DeploymentPackage(id, version, "Licensed Suite", "licence-bound test package",
            true, "Licensed Suite",
            Array.Empty<PackageFileComponent>(),
            new[] { new PackageLicenceComponent("suite-licence", hash) },
            Def($"{id}-install-{version}",
                RemediationStep.Create("install", RemediationStepKinds.RunScript,
                    scriptBody: "setup.exe /quiet /licence {licence:suite-licence}")),
            Def($"{id}-uninstall-{version}",
                RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "Licensed Suite")));
    }

    // ---- repository + manifest ------------------------------------------

    [Fact]
    public void Package_CanonicalRoundTrip_PreservesComponentsAndHash()
    {
        var rig = new Rig();
        var pkg = LicensedPkg(rig);
        var round = DeploymentPackage.FromCanonicalJson(pkg.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(pkg.ContentHash, round!.ContentHash);
        Assert.Equal(pkg.Manifest(), round.Manifest());
        Assert.DoesNotContain(LicenceValue, pkg.ToCanonicalJson());
    }

    [Fact]
    public void Repository_AdmitsValidPackage_ListingIsSecretFree()
    {
        var rig = new Rig();
        var pkg = LicensedPkg(rig);
        var (ok, reason) = rig.Repository.Admit(pkg, pkg.Manifest());
        Assert.True(ok, reason);
        var listing = Assert.Single(rig.Repository.Listings());
        Assert.Equal(new[] { "suite-licence" }, listing.LicenceRefs);
        var listingJson = System.Text.Json.JsonSerializer.Serialize(listing);
        Assert.DoesNotContain(LicenceValue, listingJson);
        Assert.DoesNotContain(LicenceValue, rig.Audit.Entries.Select(e => e.Detail).Aggregate("", (a, b) => a + b));
    }

    [Fact]
    public void Repository_SameIdVersionDifferentContent_Refused()
    {
        var rig = new Rig();
        rig.Repository.Admit(Pkg(), Pkg().Manifest());
        var evil = Pkg() with
        {
            Install = Def("widget-install-2.0.0",
                RemediationStep.Create("install", RemediationStepKinds.RunScript, scriptBody: "evil")),
        };
        var (ok, reason) = rig.Repository.Admit(evil, evil.Manifest());
        Assert.False(ok);
        Assert.Contains("conflicts", reason);
    }

    [Fact]
    public void Repository_PackageWithoutUninstall_Refused()
    {
        var rig = new Rig();
        var pkg = Pkg() with
        {
            Uninstall = AutomationDefinition.Create("empty", "empty", Array.Empty<RemediationStep>()),
        };
        var (ok, reason) = rig.Repository.Admit(pkg);
        Assert.False(ok);
        Assert.Contains("no steps", reason);
    }

    [Fact]
    public void Repository_Latest_UsesVersionOrderNotTextOrder()
    {
        var rig = new Rig();
        rig.Repository.Admit(Pkg(version: "9.0.0"));
        rig.Repository.Admit(Pkg(version: "10.0.0"));
        Assert.Equal("10.0.0", rig.Repository.Latest("widget")!.Version);
    }

    // ---- deployment: happy paths ------------------------------------------

    [Fact]
    public void Deploy_TargetedDevice_ExecutesViaEngine_StateRecorded_JobDone_AuditChained()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg());
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.True(result.Dispatched, result.Outcome);
        // AMENDED by the D38 fix lane (cross-lane, RMM-08 D38-F9):
        // wait steps now reach the executor like every other kind
        // (the executor is the host's pacing primitive), so the
        // authored "pre" wait is recorded alongside "install". The
        // claim under test — the package's steps execute via the
        // engine, in authored order — is unchanged.
        Assert.Equal(new[] { "pre", "install" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        var state = rig.Service.StateFor(Dev, "widget");
        Assert.NotNull(state);
        Assert.Equal(DevicePackageState.Deployed, state!.Status);
        Assert.Equal("2.0.0", state.InstalledVersion);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(DeploymentOutcomes.Succeeded, exec.Outcome);
        var job = rig.Service.Journal.GetJob(exec.JobId!);
        Assert.NotNull(job);
        Assert.Equal(JobKinds.Deployment, job!.Kind);
        Assert.Equal(JobStates.Done, job.State);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "deployment_completed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Deploy_LicensedPackage_KeyReachesExecutor_NeverAuditListingOrRecords()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(LicensedPkg(rig));
        string? seenByExecutor = null;
        rig.Executor.Hooks["install"] = () => { };
        rig.Executor.Results["install"] = StepRunResult.Success("installed");
        // The recording executor records (stepId, kind) only; capture
        // the materialized script body through a wrapping probe:
        var probe = new ProbeExecutor(rig.Executor);
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, probe, null, () => rig.Now);
        svc.InstalledVersionProbe = rig.ProbeInstalled;
        svc.Assign("suite", "1.0.0", new[] { Group }, "test-admin");
        var result = svc.Deploy("suite", "1.0.0", Dev, T0);
        Assert.True(result.Dispatched, result.Outcome);
        seenByExecutor = probe.LastScriptBody;
        Assert.NotNull(seenByExecutor);
        Assert.Contains(LicenceValue, seenByExecutor); // the key DID reach the execution context
        Assert.DoesNotContain("{licence:", seenByExecutor);
        // …and appears NOWHERE else:
        var auditText = string.Join("\n", rig.Audit.Entries.Select(e => e.Kind + "|" + e.Actor + "|" + e.Detail));
        Assert.DoesNotContain(LicenceValue, auditText);
        var listingJson = System.Text.Json.JsonSerializer.Serialize(rig.Repository.Listings());
        Assert.DoesNotContain(LicenceValue, listingJson);
        var exec = Assert.Single(svc.Executions);
        Assert.Equal(new[] { "suite-licence" }, exec.LicenceRefsRevealed); // refs recorded, values never
    }

    /// <summary>Test probe: records the materialized step fields the
    /// inner executor actually received.</summary>
    public sealed class ProbeExecutor : IRemediationStepExecutor, IPatchRerunTarget
    {
        private readonly RecordingRemediationStepExecutor _inner;
        public ProbeExecutor(RecordingRemediationStepExecutor inner) => _inner = inner;
        public string? LastScriptBody { get; private set; }
        public StepRunResult Execute(RemediationStep step, RemediationExecutionContext context)
        {
            // Record the last NON-NULL script body: later steps with
            // no body (e.g. an uninstall_app step) must not erase the
            // evidence of what the install step actually received.
            if (step.ScriptBody is not null) LastScriptBody = step.ScriptBody;
            return _inner.Execute(step, context);
        }
        public StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context) =>
            _inner.RerunPatch(patchEntryId, context);
    }

    [Fact]
    public void Uninstall_AfterDeploy_ExecutesUninstallDefinition_StateFlips()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg());
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        var result = rig.Service.Uninstall("widget", Dev, T0.AddMinutes(5));
        Assert.True(result.Dispatched, result.Outcome);
        Assert.Contains(rig.Executor.Calls, c => c.StepId == "uninstall");
        Assert.Equal(DevicePackageState.Uninstalled, rig.Service.StateFor(Dev, "widget")!.Status);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "deployment_completed" && e.Detail.Contains("action=uninstall"));
    }

    [Fact]
    public void Deploy_FilePackage_FetchesViaStore_Executes()
    {
        var rig = new Rig();
        var payload = Encoding.UTF8.GetBytes("widget-installer-bytes");
        var manifest = ContentManifest.Build(payload, label: "widget");
        var pkg = Pkg() with
        {
            Files = new[] { new PackageFileComponent("widget-setup.bin", manifest.ContentHash, payload.Length, @"C:\Temp\widget-setup.bin") },
        };
        rig.AdmitAndAssign(pkg);
        var hubStore = new PeerContentStore();
        Assert.True(hubStore.PutVerified(manifest, payload));
        rig.Service.PayloadFetcher = (p, device) =>
        {
            var local = new PeerContentStore();
            var fetcher = new ContentFetcher();
            var res = fetcher.Fetch(manifest, new IContentSource[] { new StoreContentSource("hub", hubStore, isHub: true) }, local);
            return res.Ok ? local : null;
        };
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.True(result.Dispatched, result.Outcome);
    }

    [Fact]
    public void Deploy_FilePackage_NoPayloadSeam_RefusedNotFileless()
    {
        var rig = new Rig();
        var payload = Encoding.UTF8.GetBytes("bytes");
        var manifest = ContentManifest.Build(payload);
        var pkg = Pkg() with
        {
            Files = new[] { new PackageFileComponent("f.bin", manifest.ContentHash, payload.Length, @"C:\Temp\f.bin") },
        };
        rig.AdmitAndAssign(pkg);
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("payload seam", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- policy + targeting gates -------------------------------------------

    [Fact]
    public void Deploy_PolicyKillSwitch_Refuses_Audited()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg());
        rig.SetPolicy(DeploymentPolicyKeys.DeploymentEnabled, "false", "off-1");
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("rmm.software_deployment.enabled", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Deploy_PerPackagePolicyDisable_RefusesOnlyThatPackage()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg());
        rig.AdmitAndAssign(Pkg(id: "gadget", version: "1.0.0"));
        rig.SetPolicy(DeploymentPolicyKeys.PackageEnabled("widget"), "false", "off-widget");
        Assert.False(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
        Assert.True(rig.Service.Deploy("gadget", "1.0.0", Dev, T0).Dispatched);
    }

    [Fact]
    public void Deploy_NoAssignment_Refuses_DeploymentByPolicy()
    {
        var rig = new Rig();
        Assert.True(rig.Service.AdmitLocalPackage(Pkg(), "test").Allowed);
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("target set", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Deploy_DynamicGroupTargeting_AttributeRuleAdmits()
    {
        var rig = new Rig();
        rig.Policy.AddGroup(new GroupDefinition("grp-site-a", "Site A",
            new[] { new GroupRule("attribute_equals", "site", "alpha") }));
        var factsA = StaticDeviceFacts.Of("dev-a", Scope, attributes: new Dictionary<string, string> { ["site"] = "alpha" });
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == "dev-a" ? factsA : null, rig.Signer, rig.Gate,
            rig.Repository, rig.Vault, rig.Executor, null, () => rig.Now);
        svc.InstalledVersionProbe = rig.ProbeInstalled;
        Assert.True(svc.AdmitLocalPackage(Pkg(), "test").Allowed);
        svc.Assign("widget", "2.0.0", new[] { "grp-site-a" }, "test-admin");
        Assert.True(svc.Deploy("widget", "2.0.0", "dev-a", T0).Dispatched);
    }

    [Fact]
    public void Deploy_DisabledTemplatePackage_Refuses()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg(enabled: false));
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Deploy_RevokedPackage_Refuses()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg());
        rig.Repository.Revoke("widget", "2.0.0");
        var result = rig.Service.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("revoked", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Deploy_NoSigner_Refuses()
    {
        var rig = new Rig(signer: false);
        rig.AdmitAndAssign(Pkg());
        var svc = new SoftwareDeploymentService(rig.Audit, rig.Policy,
            id => id == Dev ? rig.Facts : null, null, rig.Gate,
            rig.Repository, rig.Vault, rig.Executor, null, () => rig.Now);
        svc.Assign("widget", "2.0.0", new[] { Group }, "test-admin");
        var result = svc.Deploy("widget", "2.0.0", Dev, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("signer", result.Outcome);
    }

    // ---- downgrade -----------------------------------------------------------

    [Fact]
    public void Upgrade_DeployNewerOverOlder_Succeeds()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg(version: "1.0.0"));
        Assert.True(rig.Service.Deploy("widget", "1.0.0", Dev, T0).Dispatched);
        // AMENDED by the D38 fix lane (F10): both versions were
        // originally assigned up front; under the corrected
        // one-desired-version semantics, assigning 2.0.0 supersedes
        // the 1.0.0 assignment, so 1.0.0 is deployed BEFORE 2.0.0 is
        // assigned. The upgrade path under test is unchanged.
        rig.AdmitAndAssign(Pkg(version: "2.0.0"));
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0.AddMinutes(1)).Dispatched);
        Assert.Equal("2.0.0", rig.Service.StateFor(Dev, "widget")!.InstalledVersion);
    }

    // ---- signed delivery -------------------------------------------------------

    [Fact]
    public void SignedPackageDelivery_ValidEnvelope_Admitted_AndDeployable()
    {
        var rig = new Rig();
        var pkg = Pkg();
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(pkg.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedPackage(env);
        Assert.True(verdict.Allowed, verdict.Reason);
        rig.Service.Assign("widget", "2.0.0", new[] { Group }, "test-admin");
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);
    }

    [Fact]
    public void SignedContentPackDelivery_AdmittedWhole_StaleRevisionRefused()
    {
        var rig = new Rig();
        var pack = StarterContentPacks.RuntimePack();
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(pack.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Service.ApplySignedContentPack(env).Allowed);
        Assert.NotNull(rig.Repository.Get("dotnet-desktop-runtime", "8.0.0"));
        // Same pack again: idempotent.
        var env2 = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(pack.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Service.ApplySignedContentPack(env2).Allowed);
        // A conflicting same-revision pack refuses whole.
        var conflict = new ContentPack(StarterContentPacks.RuntimePackId, 1, new[] { Pkg(id: "impostor") });
        var env3 = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(conflict.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.False(rig.Service.ApplySignedContentPack(env3).Allowed);
        Assert.Null(rig.Repository.Get("impostor", "2.0.0"));
    }

    // ---- starter packs -----------------------------------------------------------

    [Fact]
    public void StarterPacks_AreValid_RuntimeAndUtilitiesEnabled_BasTemplateDisabled()
    {
        foreach (var pack in StarterContentPacks.All())
            Assert.Null(pack.Validate());
        Assert.All(StarterContentPacks.RuntimePack().Packages, p => Assert.True(p.Enabled));
        Assert.All(StarterContentPacks.UtilitiesPack().Packages, p => Assert.True(p.Enabled));
        var bas = Assert.Single(StarterContentPacks.BasWorkstationPack().Packages);
        Assert.False(bas.Enabled);
        Assert.False(bas.Install.Enabled);
        Assert.Contains("<SITE_", bas.Description + bas.Install.Steps[0].Target);
    }

    [Fact]
    public void StarterPacks_AsFiles_RoundTripThroughCanonicalJson()
    {
        var files = StarterContentPacks.AsFiles();
        Assert.Equal(3, files.Count);
        foreach (var (name, bytes) in files)
        {
            var pack = ContentPack.FromCanonicalJson(Encoding.UTF8.GetString(bytes));
            Assert.NotNull(pack);
            Assert.Null(pack!.Validate());
        }
    }

    [Fact]
    public void SeedStarterPacks_RuntimeUtilitiesAdmit_BasTemplateRefusesOnPlaceholderLicence()
    {
        var rig = new Rig();
        var results = rig.Service.SeedStarterPacks();
        Assert.True(results.Single(r => r.PackId == StarterContentPacks.RuntimePackId).Verdict.Allowed);
        Assert.True(results.Single(r => r.PackId == StarterContentPacks.UtilitiesPackId).Verdict.Allowed);
        var bas = results.Single(r => r.PackId == StarterContentPacks.BasWorkstationPackId);
        Assert.False(bas.Verdict.Allowed); // placeholder licence hash matches no vault key — by design
        Assert.Contains("licence", bas.Verdict.Reason);
        Assert.Null(rig.Repository.Get("bas-workstation-suite", "1.0.0"));
    }

    // ---- convergence --------------------------------------------------------------

    [Fact]
    public void Convergence_CompliantDriftedMissingUnmanaged_NamedHonestly()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg(version: "2.0.0"));
        Assert.True(rig.Service.Deploy("widget", "2.0.0", Dev, T0).Dispatched);

        var observedMatch = new[] { new SoftwareItem("Widget", "2.0.0", null, null, null) };
        var line = Assert.Single(rig.Service.ConvergenceFor(Dev, observedMatch));
        Assert.Equal(ConvergenceStates.Compliant, line.State);

        var observedOld = new[] { new SoftwareItem("Widget", "1.5.0", null, null, null) };
        line = Assert.Single(rig.Service.ConvergenceFor(Dev, observedOld));
        Assert.Equal(ConvergenceStates.Drifted, line.State); // machine disagrees with the record

        line = Assert.Single(rig.Service.ConvergenceFor(Dev2, Array.Empty<SoftwareItem>()));
        Assert.Equal(ConvergenceStates.Missing, line.State);

        line = Assert.Single(rig.Service.ConvergenceFor(Dev2, observedMatch));
        Assert.Equal(ConvergenceStates.Unmanaged, line.State); // installed, but ACP never deployed it there
    }

    [Fact]
    public void Convergence_DesiredVersionChange_ReadsDrifted()
    {
        var rig = new Rig();
        rig.AdmitAndAssign(Pkg(version: "1.0.0"));
        Assert.True(rig.Service.Deploy("widget", "1.0.0", Dev, T0).Dispatched);
        rig.AdmitAndAssign(Pkg(version: "2.0.0")); // assignment now desires 2.0.0
        var observed = new[] { new SoftwareItem("Widget", "1.0.0", null, null, null) };
        var lines = rig.Service.ConvergenceFor(Dev, observed);
        Assert.Contains(lines, l => l.DesiredVersion == "2.0.0" && l.State == ConvergenceStates.Drifted);
    }
}
