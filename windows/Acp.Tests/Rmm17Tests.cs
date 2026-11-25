using System.Text;
using Acp.Core.Services;
using Acp.Shared.EndpointSecurity;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-17 — Endpoint security posture: ransomware auto-isolation +
// AV/EDR management. Detector bar, isolation state machine + narrow
// ACP exemption, hub-signed-only release, AV posture (missing /
// disabled / stale, incl. stale-source anti-lying), policy floors,
// RMM-01 alert feed, signed AV management intents. All file
// activity and AV readings come from fakes; no real files outside
// test temp dirs are touched and no network is altered (the network
// control is a recording fake).
public class Rmm17Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ---- fixtures ------------------------------------------------------

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public AlertCenter Dir57 = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public FakeFileActivitySource Files = new();
        public FakeNetworkControl Net = new();
        public FakeAvStatusSource Av = new();
        public RansomwareDetector Detector = new(new[] { @"C:\canary\canary-doc.docx" });
        public EndpointIsolationManager Isolation;
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public EndpointSecurityService Service;

        public Rig()
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Isolation = new EndpointIsolationManager(Dev, Net, Audit);
            Service = new EndpointSecurityService(Dev, Facts, Policy, Detector, Files,
                Isolation, DefaultPlan(), Av, Centre, Audit, Gate, () => Now);
        }

        public static IsolationPlan DefaultPlan() => new(new[]
        {
            new AcpChannelExemption(ExemptionKinds.Hub, "hub.acp.local", 8443),
            new AcpChannelExemption(ExemptionKinds.LanRung, "hub.acp.local", 40117),
            new AcpChannelExemption(ExemptionKinds.Tailscale, "100.64.0.7", 8443),
        });

        public void SetPolicy(string key, string value, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument($"doc-{key}-{rev}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev));

        public SignedCommandEnvelope SignPayload(string payload, string cls = "automation") =>
            Signer.Sign(cls, Encoding.UTF8.GetBytes(payload), Now, TimeSpan.FromMinutes(10));

        public SignedCommandEnvelope UnisolateEnvelope(string device = Dev) =>
            SignPayload($"{{\"action\":\"rmm17.unisolate\",\"deviceId\":\"{device}\"}}");
    }

    private static FileActivityEvent Ev(string path, string kind = "modified",
        double? entropy = null, string? old = null, string proc = "evil.exe", DateTimeOffset? at = null) =>
        new(path, kind, old, entropy, proc, at ?? T0);

    /// <summary>A full ransomware burst: 60 files modified, 30 of
    /// them renames, 25 at high entropy, plus a ransom note.</summary>
    private static FileActivityEvent[] RansomwareBurst()
    {
        var list = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            list.Add(Ev($@"C:\Users\j\doc{i}.locked", "renamed", 7.9, old: $@"C:\Users\j\doc{i}.docx"));
        for (var i = 30; i < 60; i++)
            list.Add(Ev($@"C:\Users\j\file{i}.dat", "modified", i < 55 ? 7.8 : 3.0));
        list.Add(Ev(@"C:\Users\j\README_DECRYPT.txt", "created", 4.0));
        return list.ToArray();
    }

    private static AvStatusReading Reading(string product = "defender", bool installed = true,
        bool enabled = true, bool rt = true, DateTimeOffset? defs = null,
        DateTimeOffset? observed = null, bool alive = true, string claimed = "healthy") =>
        new(product, installed, enabled, rt, defs ?? T0.AddHours(-2), T0.AddDays(-1),
            observed ?? T0, alive, claimed);

    // ---- detector: the bar ----------------------------------------------

    [Fact]
    public void Detector_FullRansomwareBurst_MeetsTheBar()
    {
        var d = new RansomwareDetector();
        d.Ingest(RansomwareBurst());
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.True(v.ShouldIsolate, v.Detail);
        Assert.Contains(SignalFamilies.MassModification, v.FamiliesPresent);
        Assert.True(v.FamiliesPresent.Count >= 3, v.Detail);
    }

    [Fact]
    public void Detector_SingleSignal_NeverIsolates()
    {
        // Mass writes only (one family).
        var d1 = new RansomwareDetector();
        d1.Ingest(Enumerable.Range(0, 80).Select(i => Ev($@"C:\data\f{i}.bin", "modified", 3.0)));
        Assert.False(d1.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);

        // Rename storm only.
        var d2 = new RansomwareDetector();
        d2.Ingest(Enumerable.Range(0, 40).Select(i => Ev($@"C:\data\r{i}.txt", "renamed", 3.0, old: $@"C:\data\o{i}.txt")));
        Assert.False(d2.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);

        // Entropy surge only, few files.
        var d3 = new RansomwareDetector();
        d3.Ingest(Enumerable.Range(0, 25).Select(i => Ev($@"C:\data\e{i}.bin", "modified", 7.9)));
        Assert.False(d3.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);
    }

    [Fact]
    public void Detector_TwoFamilies_DoNotIsolate()
    {
        // Mass + renames, but low entropy, no artifacts: 2 families.
        var d = new RansomwareDetector();
        var events = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            events.Add(Ev($@"C:\data\r{i}.txt", "renamed", 3.0, old: $@"C:\data\o{i}.txt"));
        for (var i = 30; i < 60; i++)
            events.Add(Ev($@"C:\data\f{i}.bin", "modified", 3.0));
        d.Ingest(events);
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Equal(2, v.FamiliesPresent.Count);
        Assert.False(v.ShouldIsolate, v.Detail);
    }

    [Fact]
    public void Detector_OldActivity_AgesOutOfTheWindow()
    {
        var d = new RansomwareDetector();
        foreach (var e in RansomwareBurst())
            d.Ingest(new[] { e with { AtUtc = T0.AddMinutes(-10) } });
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.False(v.ShouldIsolate, v.Detail);
        Assert.Equal(0, v.DistinctFiles);
    }

    [Fact]
    public void Detector_UnmeasuredEntropy_NeverCountsTowardEntropySignal()
    {
        var d = new RansomwareDetector();
        var events = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            events.Add(Ev($@"C:\data\r{i}.locked", "renamed", null, old: $@"C:\data\o{i}.docx"));
        for (var i = 30; i < 60; i++)
            events.Add(Ev($@"C:\data\f{i}.bin", "modified", null));
        d.Ingest(events);
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Equal(0, v.HighEntropyFiles);
        // mass + rename + ransom-extension artifact = 3 families: isolates
        // on the OTHER signals — entropy contributed nothing. (D38-F10:
        // the isolation outcome is ASSERTED, not just commented.)
        Assert.DoesNotContain(SignalFamilies.EntropySurge, v.FamiliesPresent);
        Assert.True(v.ShouldIsolate, v.Detail);
    }

    // ---- service: isolation flow ------------------------------------------

    [Fact]
    public void Service_RansomwareBurst_Isolates_RaisesCritical_KeepsAcpChannel()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        var r = rig.Service.RunDetectionCycle();
        Assert.True(r.IsolationApplied, r.Detail);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        Assert.True(rig.Net.IsIsolationApplied);
        // CRITICAL alert in the RMM-01 centre.
        var alert = Assert.Single(rig.Centre.ActiveAlerts);
        Assert.Equal(AlertSeverities.Critical, alert.Severity);
        Assert.Equal(Rmm17AlertKinds.RansomwareIsolation, alert.Kind);
        // The ACP channel survives; everything else does not.
        var plan = rig.Net.AppliedPlan!;
        Assert.True(plan.IsTrafficAllowed("hub.acp.local", 8443));
        Assert.True(plan.IsTrafficAllowed("hub.acp.local", 40117)); // the rung's exact peer host (D38-F3)
        Assert.False(plan.IsTrafficAllowed(null, 40117));
        Assert.False(plan.IsTrafficAllowed("192.168.1.50", 40117)); // foreign LAN host on the rung port
        Assert.True(plan.IsTrafficAllowed("100.64.0.7", 8443));
        Assert.False(plan.IsTrafficAllowed("192.168.1.50", 445));
        Assert.False(plan.IsTrafficAllowed("hub.acp.local", 445)); // right host, wrong port
        Assert.False(plan.IsTrafficAllowed("evil.example", 8443)); // right port, wrong host
        // The user sees it, plainly.
        Assert.False(string.IsNullOrWhiteSpace(rig.Isolation.Status.BannerText));
        Assert.Contains("ISOLATED", rig.Isolation.Status.BannerText);
        // Chained.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_isolated");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Service_Isolation_IsIdempotentAcrossCycles()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        Assert.Equal(1, rig.Net.ApplyCount);
        Assert.Single(rig.Centre.Alerts.Where(a => a.Kind == Rmm17AlertKinds.RansomwareIsolation));
    }

    [Fact]
    public void Service_AutoIsolationOffByPolicy_AlertsButDoesNotIsolate()
    {
        var rig = new Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.AutoIsolation, "false");
        rig.Files.Enqueue(RansomwareBurst());
        var r = rig.Service.RunDetectionCycle();
        Assert.False(r.IsolationApplied);
        Assert.Equal(IsolationStates.Normal, rig.Isolation.Status.State);
        Assert.Single(rig.Centre.ActiveAlerts); // alert still raised
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "ransomware_detected_no_auto_isolation");
    }

    [Fact]
    public void Service_FeatureDisabledByPolicy_IsInert_AndDrainsActivity()
    {
        var rig = new Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.Enabled, "false");
        rig.Files.Enqueue(RansomwareBurst());
        var r = rig.Service.RunDetectionCycle();
        Assert.False(r.FeatureEnabled);
        Assert.Equal(IsolationStates.Normal, rig.Isolation.Status.State);
        Assert.Empty(rig.Centre.ActiveAlerts);
        // Re-enabling does not retro-fire the drained burst.
        rig.SetPolicy(EndpointSecurityPolicyKeys.Enabled, "true", rev: 2);
        var r2 = rig.Service.RunDetectionCycle();
        Assert.False(r2.Verdict!.ShouldIsolate);
    }

    // ---- un-isolate: hub-signed only ---------------------------------------

    [Fact]
    public void Unisolate_SignedHubCommand_Releases_AndResetsDetector()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        var (applied, detail) = rig.Service.HandleSignedUnisolate(rig.UnisolateEnvelope());
        Assert.True(applied, detail);
        Assert.Equal(IsolationStates.Normal, rig.Isolation.Status.State);
        Assert.False(rig.Net.IsIsolationApplied);
        Assert.Equal(0, rig.Detector.WindowEventCount);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_unisolated");
    }

    [Fact]
    public void Unisolate_UnsignedOrLocal_Refuses()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        Assert.False(rig.Service.HandleSignedUnisolate(null).Applied);
        var (local, _) = rig.Service.TryLocalUnisolate("local-admin");
        Assert.False(local);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_unisolate_refused_local");
    }

    [Fact]
    public void Unisolate_SignedForAnotherDevice_Refuses()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        var (applied, _) = rig.Service.HandleSignedUnisolate(rig.UnisolateEnvelope("dev-2"));
        Assert.False(applied);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    [Fact]
    public void Unisolate_SignedWrongAction_Refuses()
    {
        var rig = new Rig();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        var env = rig.SignPayload("{\"action\":\"rmm17.something_else\",\"deviceId\":\"dev-1\"}");
        Assert.False(rig.Service.HandleSignedUnisolate(env).Applied);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // ---- isolation plan discipline ------------------------------------------

    [Fact]
    public void Plan_NoExemption_Refuses_EmptyPlanWouldCutAcp()
    {
        var plan = new IsolationPlan(Array.Empty<AcpChannelExemption>());
        Assert.NotNull(plan.Validate());
        var rig = new Rig();
        var (applied, _) = rig.Isolation.Isolate(plan, "test", T0);
        Assert.False(applied);
        Assert.Equal(IsolationStates.Normal, rig.Isolation.Status.State);
    }

    [Fact]
    public void Exemption_WildcardOrCidrHost_Refuses()
    {
        Assert.NotNull(new AcpChannelExemption(ExemptionKinds.Hub, "*", 8443).Validate());
        Assert.NotNull(new AcpChannelExemption(ExemptionKinds.Hub, "192.168.1.0/24", 8443).Validate());
        Assert.NotNull(new AcpChannelExemption(ExemptionKinds.Hub, "hub.acp.local", 0).Validate());
        Assert.NotNull(new AcpChannelExemption("arbitrary", "x", 1).Validate());
        Assert.Null(new AcpChannelExemption(ExemptionKinds.Hub, "hub.acp.local", 8443).Validate());
    }

    // ---- policy floors --------------------------------------------------------

    [Fact]
    public void Policy_CannotLowerTheBar_BelowFloors()
    {
        var rig = new Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.MinSignalFamilies, "1");
        var p = rig.Service.CurrentPolicy(T0);
        Assert.Equal(RansomwareThresholds.FloorMinFamilies, p.Thresholds.MinSignalFamilies);
        Assert.NotEmpty(p.ClampNotes);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_security_policy_clamped");

        var rig2 = new Rig();
        rig2.SetPolicy(EndpointSecurityPolicyKeys.MassFileThreshold, "5");
        Assert.Equal(RansomwareThresholds.FloorMassFiles,
            rig2.Service.CurrentPolicy(T0).Thresholds.MassFileThreshold);
    }

    [Fact]
    public void Policy_CanRaiseTheBar()
    {
        var rig = new Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.MassFileThreshold, "500");
        Assert.Equal(500, rig.Service.CurrentPolicy(T0).Thresholds.MassFileThreshold);
        rig.Files.Enqueue(RansomwareBurst()); // 60 files < 500
        var r = rig.Service.RunDetectionCycle();
        Assert.False(r.IsolationApplied);
    }

    // ---- AV posture -------------------------------------------------------------

    [Fact]
    public void Av_HealthyProduct_ReadsProtected_NoAlert()
    {
        var rig = new Rig();
        rig.Av.Set(Reading());
        var report = rig.Service.RefreshAvPosture();
        Assert.NotNull(report);
        Assert.True(report!.AnyProtected);
        Assert.False(report.HasGap);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void Av_Disabled_FlagsCritical_UnderNeverSuppressibleKind()
    {
        var rig = new Rig();
        rig.Av.Set(Reading(enabled: false, rt: false));
        var report = rig.Service.RefreshAvPosture();
        Assert.Contains(report!.Findings, f => f.State == AvPostureStates.Disabled);
        var alert = Assert.Single(rig.Centre.ActiveAlerts);
        Assert.Equal(ConditionKinds.SecurityAvOff, alert.Kind);
        Assert.Equal(AlertSeverities.Critical, alert.Severity);
        Assert.True(ConditionKinds.NeverSuppressible.Contains(alert.Kind));
    }

    [Fact]
    public void Av_RequiredProductAbsent_FlagsMissing()
    {
        var rig = new Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.RequiredAv, "crowdstrike");
        rig.Av.Set(Reading("defender")); // healthy, but not the org's chosen tool
        var report = rig.Service.RefreshAvPosture();
        Assert.Contains(report!.Findings,
            f => f.ProductId == "crowdstrike" && f.State == AvPostureStates.Missing);
    }

    [Fact]
    public void Av_NoReadingsAtAll_FlagsMissing_NotHealthy()
    {
        var rig = new Rig();
        rig.Av.Set();
        var report = rig.Service.RefreshAvPosture();
        Assert.False(report!.AnyProtected);
        Assert.Contains(report.Findings, f => f.State == AvPostureStates.Missing);
    }

    [Fact]
    public void Av_StaleDefinitions_ReadStale()
    {
        var rig = new Rig();
        rig.Av.Set(Reading(defs: T0.AddDays(-30)));
        var report = rig.Service.RefreshAvPosture();
        Assert.Contains(report!.Findings, f => f.State == AvPostureStates.Stale);
        Assert.DoesNotContain(report.Findings, f => f.State == AvPostureStates.Protected);
    }

    [Fact]
    public void Av_GapClosing_AutoResetsTheAlert()
    {
        var rig = new Rig();
        rig.Av.Set(Reading(enabled: false, rt: false));
        rig.Service.RefreshAvPosture();
        Assert.Single(rig.Centre.ActiveAlerts);
        rig.Av.Set(Reading());
        rig.Service.RefreshAvPosture();
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void Av_UnknownProduct_IsFlaggedUnknown_NotTrusted()
    {
        var rig = new Rig();
        rig.Av.Set(Reading("mystery-av-9000"));
        var report = rig.Service.RefreshAvPosture();
        Assert.Contains(report!.Findings, f => f.State == AvPostureStates.Unknown);
        Assert.False(report.AnyProtected);
    }

    // ---- AV management intents ---------------------------------------------------

    [Fact]
    public void AvIntent_Build_ValidatesProductAndAction()
    {
        var (ok, _) = AvManagementIntent.Build("defender", "deploy", Dev);
        Assert.NotNull(ok);
        Assert.Equal(SignedCommandClasses.PackageDeploy, ok!.CommandClass);
        var (cfg, _) = AvManagementIntent.Build("defender", "configure", Dev);
        Assert.Equal(SignedCommandClasses.Automation, cfg!.CommandClass);
        Assert.Null(AvManagementIntent.Build("nope-av", "deploy", Dev).Intent);
        Assert.Null(AvManagementIntent.Build("trellix", "configure", Dev).Intent); // SupportsConfigure=false
        Assert.Null(AvManagementIntent.Build("defender", "become_the_av", Dev).Intent);
    }

    [Fact]
    public void AvIntent_SignedCommand_Verifies_TamperedRefuses()
    {
        var rig = new Rig();
        var (intent, _) = rig.Service.CreateAvManagementIntent("defender", "update_definitions");
        Assert.NotNull(intent);
        var env = rig.Signer.Sign(intent!.CommandClass,
            Encoding.UTF8.GetBytes(intent.PayloadJson), rig.Now, TimeSpan.FromMinutes(10));
        var (verified, detail) = rig.Service.ApplyAvManagementCommand(intent, env);
        Assert.True(verified, detail);
        Assert.Contains("host wiring", detail); // execution honestly NOT claimed

        // A signed command whose payload is a DIFFERENT intent refuses.
        var (other, _) = rig.Service.CreateAvManagementIntent("defender", "run_scan");
        var (verified2, _) = rig.Service.ApplyAvManagementCommand(intent,
            rig.Signer.Sign(other!.CommandClass, Encoding.UTF8.GetBytes(other.PayloadJson),
                rig.Now, TimeSpan.FromMinutes(10)));
        Assert.False(verified2);
    }

    // ---- report ---------------------------------------------------------------------

    [Fact]
    public void Report_CarriesIsolationVerdictAndPosture()
    {
        var rig = new Rig();
        rig.Av.Set(Reading());
        rig.Service.RefreshAvPosture();
        rig.Files.Enqueue(RansomwareBurst());
        rig.Service.RunDetectionCycle();
        var report = rig.Service.BuildReport();
        Assert.True(report.FeatureEnabled);
        Assert.True(report.Isolation.IsIsolated);
        Assert.NotNull(report.LastVerdict);
        Assert.NotNull(report.AvPosture);
        Assert.True(report.AvPosture!.AnyProtected);
    }
}
