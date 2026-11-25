using System.Text;
using Acp.Shared.EndpointSecurity;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-17 D38 FIX lane — regression tests for packet aa8d9f10
// (12 findings). Attempt-1 had already landed the model-side fixes
// for F1/F3/F4/F7/F8/F9/F10/F11 and the F12 fake removal in
// EndpointSecurity.cs, but left the test doubles uncreated, the
// Rig's LAN-rung exemption in the old null-host shape, and F2/F5
// unfixed in the service. These tests pin every finding.
public class Rmm17FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";

    private static FileActivityEvent Ev(string path, string kind = "modified",
        double? entropy = null, string? old = null, DateTimeOffset? at = null) =>
        new(path, kind, old, entropy, "evil.exe", at ?? T0);

    private static List<FileActivityEvent> Burst()
    {
        var list = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            list.Add(Ev($@"C:\Users\j\doc{i}.locked", "renamed", 7.9, $@"C:\Users\j\doc{i}.docx"));
        for (var i = 30; i < 60; i++)
            list.Add(Ev($@"C:\Users\j\file{i}.dat", "modified", 7.8));
        list.Add(Ev(@"C:\Users\j\README_DECRYPT.txt", "created", 4.0));
        return list;
    }

    private static AvStatusReading Reading(string product = "defender", bool installed = true,
        bool enabled = true, bool rt = true, DateTimeOffset? defs = null,
        DateTimeOffset? observed = null, bool alive = true) =>
        new(product, installed, enabled, rt, defs ?? T0.AddHours(-2), T0.AddDays(-1),
            observed ?? T0, alive, "healthy");

    // F1 — mass + rename + entropy with NO ransom artifact (the
    // photo-organiser / compressing-backup shape on non-archive
    // files) must NOT isolate: the artifact family is REQUIRED.
    [Fact]
    public void F1_BehaviourAlone_NoArtifact_NeverIsolates()
    {
        var d = new RansomwareDetector();
        var evs = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            evs.Add(Ev($@"C:\data\r{i}.dat", "renamed", 7.9, $@"C:\data\o{i}.dat"));
        for (var i = 30; i < 60; i++)
            evs.Add(Ev($@"C:\data\f{i}.dat", "modified", 7.9));
        d.Ingest(evs);
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Contains(SignalFamilies.MassModification, v.FamiliesPresent);
        Assert.Contains(SignalFamilies.RenameBurst, v.FamiliesPresent);
        Assert.Contains(SignalFamilies.EntropySurge, v.FamiliesPresent);
        Assert.DoesNotContain(SignalFamilies.RansomArtifact, v.FamiliesPresent);
        Assert.False(v.ShouldIsolate, v.Detail);
    }

    // F2a — while isolated, the alert re-raises EVERY cycle, even
    // after the burst has aged out of the window (the original code
    // returned early on !ShouldIsolate and the alert could be lost
    // to a maintenance window forever).
    [Fact]
    public void F2_AlertReRaisesEveryCycleWhileIsolated_AfterBurstAgesOut()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Files.Enqueue(Burst());
        var r1 = rig.Service.RunDetectionCycle();
        Assert.True(r1.IsolationApplied);
        Assert.Equal(RaiseOutcome.New, r1.AlertOutcome);
        rig.Now = T0.AddMinutes(10); // burst is long out of the 60 s window
        var r2 = rig.Service.RunDetectionCycle(); // no new activity
        Assert.True(r2.IsolationApplied);
        Assert.Equal(RaiseOutcome.Refreshed, r2.AlertOutcome);
        Assert.Single(rig.Centre.ActiveAlerts); // deduped refresh, not a duplicate
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // F2b — a FAILED actuation retries on a later cycle even when
    // no new activity meets the bar (the original code only retried
    // when a fresh burst re-fired the verdict).
    [Fact]
    public void F2_IsolationFailed_RetriesWithoutFreshBurst()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Net.ThrowOnApply = true;
        rig.Files.Enqueue(Burst());
        var r1 = rig.Service.RunDetectionCycle();
        Assert.False(r1.IsolationApplied);
        Assert.Equal(IsolationStates.IsolationFailed, rig.Isolation.Status.State);
        rig.Net.ThrowOnApply = false;
        rig.Now = T0.AddMinutes(10); // window aged out; no fresh burst
        var r2 = rig.Service.RunDetectionCycle();
        Assert.True(r2.IsolationApplied, r2.Detail);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // F3 — the LAN rung can no longer express "any host on a port":
    // a null-host rung exemption refuses validation outright, and
    // SMB (445) to a LAN peer is blocked even under a rung-shaped
    // exemption for another host.
    [Fact]
    public void F3_LanRung_NullHostRefuses_ForeignHostOnRungPortBlocked()
    {
        Assert.NotNull(new AcpChannelExemption(ExemptionKinds.LanRung, null, 40117).Validate());
        var plan = new IsolationPlan(new[]
        {
            new AcpChannelExemption(ExemptionKinds.LanRung, "192.168.10.5", 445),
        });
        Assert.Null(plan.Validate()); // an exact-host exemption is expressible…
        Assert.True(plan.IsTrafficAllowed("192.168.10.5", 445));
        Assert.False(plan.IsTrafficAllowed("192.168.10.99", 445)); // …but only for that host
        Assert.False(plan.IsTrafficAllowed(null, 445));
    }

    // F4 — exemption host validation refuses the Windows Firewall
    // scope keywords, ranges, network/broadcast forms and partial
    // IPs that RemoteAddress would expand into broad holes.
    [Fact]
    public void F4_ExemptionHosts_ScopeKeywordsRangesAndNetworkForms_Refuse()
    {
        foreach (var bad in new[]
        {
            "Any", "LocalSubnet", "Intranet", "Internet", "localhost",
            "0.0.0.0", "::", "10.0.0.1-10.0.0.254", "10.0.0.0", "10.0.0.255",
            "10.0.0", "example", "host_name.example.com", "hub..local",
            "224.0.0.5", "*", "192.168.1.0/24",
        })
            Assert.NotNull(new AcpChannelExemption(ExemptionKinds.Hub, bad, 8443).Validate());
        Assert.Null(new AcpChannelExemption(ExemptionKinds.Hub, "192.168.1.10", 8443).Validate());
        Assert.Null(new AcpChannelExemption(ExemptionKinds.Hub, "hub.acp.local", 8443).Validate());
    }

    // F5a — an intent built for ANOTHER device, wrapped around a
    // validly signed envelope for that other device, verifies
    // NOTHING here: the device binding is checked, not assumed.
    [Fact]
    public void F5_AvIntent_ForAnotherDevice_Refused()
    {
        var rig = new Rmm17Tests.Rig();
        var (foreign, _) = AvManagementIntent.Build("defender", "update_definitions", "dev-2");
        Assert.NotNull(foreign);
        var env = rig.Signer.Sign(foreign!.CommandClass,
            Encoding.UTF8.GetBytes(foreign.PayloadJson), rig.Now, TimeSpan.FromMinutes(10));
        var (verified, detail) = rig.Service.ApplyAvManagementCommand(foreign, env);
        Assert.False(verified, detail);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "av_management_intent_binding_refused");
    }

    // F5b — a deploy intent re-labelled as class "automation" (with
    // an envelope validly signed AS automation over its payload)
    // refuses: the class is recomputed from the action.
    [Fact]
    public void F5_AvIntent_RelabelledClass_Refused()
    {
        var rig = new Rmm17Tests.Rig();
        var (deploy, _) = AvManagementIntent.Build("defender", "deploy", Dev);
        Assert.NotNull(deploy);
        var relabelled = deploy! with { CommandClass = SignedCommandClasses.Automation };
        var env = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(relabelled.PayloadJson), rig.Now, TimeSpan.FromMinutes(10));
        Assert.False(rig.Service.ApplyAvManagementCommand(relabelled, env).Verified);
    }

    // F5c — an intent whose fields name one action but whose
    // PayloadJson is ANOTHER intent's payload refuses (payload is
    // parsed and field-compared, not merely string-compared after
    // the fact).
    [Fact]
    public void F5_AvIntent_WrappingAnotherPayload_Refused()
    {
        var rig = new Rmm17Tests.Rig();
        var (scan, _) = AvManagementIntent.Build("defender", "run_scan", Dev);
        var (defs, _) = AvManagementIntent.Build("defender", "update_definitions", Dev);
        var wrapped = scan! with { PayloadJson = defs!.PayloadJson };
        var env = rig.Signer.Sign(wrapped.CommandClass,
            Encoding.UTF8.GetBytes(wrapped.PayloadJson), rig.Now, TimeSpan.FromMinutes(10));
        Assert.False(rig.Service.ApplyAvManagementCommand(wrapped, env).Verified);
    }

    // F6 — settled in the code's favour: ransomware_isolation IS in
    // RMM-01's NeverSuppressible set (RES-3 closing integration).
    [Fact]
    public void F6_RansomwareIsolation_IsNeverSuppressible()
    {
        Assert.Contains(Rmm17AlertKinds.RansomwareIsolation, ConditionKinds.NeverSuppressible);
        Assert.Contains(ConditionKinds.SecurityAvOff, ConditionKinds.NeverSuppressible);
    }

    // F7 — policy cannot lengthen the window past the 60 s ceiling:
    // 300 s clamps DOWN to 60 with a named clamp note (a longer
    // window at the same counts is a LOWER rate bar).
    [Fact]
    public void F7_WindowSeconds_AboveCeiling_ClampsTo60_WithNote()
    {
        var rig = new Rmm17Tests.Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.WindowSeconds, "300");
        var p = rig.Service.CurrentPolicy(T0);
        Assert.Equal(RansomwareThresholds.CeilWindowSeconds, p.Thresholds.WindowSeconds);
        Assert.Contains(p.ClampNotes, n => n.Contains(EndpointSecurityPolicyKeys.WindowSeconds));
    }

    // F8 — future-dated AV timestamps read STALE, never
    // fresh-forever: an observation or a definitions stamp far
    // ahead of now is a lying/stuck clock. Within the 5-minute
    // skew bound, a reading still counts.
    [Fact]
    public void F8_FutureDatedAvTimestamps_ReadStale()
    {
        var policy = EndpointSecurityPolicy.Default;
        var futureObs = AvPostureEvaluator.Evaluate(Dev,
            new[] { Reading(observed: T0.AddHours(1)) }, policy, T0);
        Assert.Contains(futureObs.Findings, f => f.State == AvPostureStates.Stale);
        Assert.DoesNotContain(futureObs.Findings, f => f.State == AvPostureStates.Protected);

        var futureDefs = AvPostureEvaluator.Evaluate(Dev,
            new[] { Reading(defs: T0.AddDays(30)) }, policy, T0);
        Assert.Contains(futureDefs.Findings, f => f.State == AvPostureStates.Stale);

        var withinSkew = AvPostureEvaluator.Evaluate(Dev,
            new[] { Reading(observed: T0.AddMinutes(2), defs: T0.AddMinutes(2)) }, policy, T0);
        Assert.Contains(withinSkew.Findings, f => f.State == AvPostureStates.Protected);
    }

    // F9 — condition ids are distinct PER PRODUCT: two products in
    // the same state raise two alerts, and one product's gap
    // closing resets only its own alert.
    [Fact]
    public void F9_ConditionIds_DistinctPerProduct_GapResetIsPerProduct()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Av.Set(Reading("defender", installed: false), Reading("crowdstrike", installed: false));
        var report = rig.Service.RefreshAvPosture();
        Assert.Contains(report!.Findings, f => f.ConditionId == "rmm17-av-defender-missing");
        Assert.Contains(report.Findings, f => f.ConditionId == "rmm17-av-crowdstrike-missing");
        Assert.Equal(2, rig.Centre.ActiveAlerts.Count(a => a.ConditionId.StartsWith("rmm17-av-")));
        // Defender recovers; crowdstrike's alert must survive.
        rig.Av.Set(Reading("defender"), Reading("crowdstrike", installed: false));
        rig.Service.RefreshAvPosture();
        Assert.DoesNotContain(rig.Centre.ActiveAlerts, a => a.ConditionId == "rmm17-av-defender-missing");
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.ConditionId == "rmm17-av-crowdstrike-missing");
    }

    // F9 (remainder) — an unregistered tool beside a PROTECTED
    // product raises no permanent security_av_off alert and does
    // not pin HasGap; alone, it is still gap evidence.
    [Fact]
    public void F9_UnknownTool_BesideProtectedProduct_NoAlertNoGap_AloneIsGap()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Av.Set(Reading("defender"), Reading("mystery-av-9000"));
        var report = rig.Service.RefreshAvPosture();
        Assert.False(report!.HasGap);
        Assert.Empty(rig.Centre.ActiveAlerts);

        var rig2 = new Rmm17Tests.Rig();
        rig2.Av.Set(Reading("mystery-av-9000"));
        var report2 = rig2.Service.RefreshAvPosture();
        Assert.True(report2!.HasGap);
        Assert.Single(rig2.Centre.ActiveAlerts);
    }

    // F10 — families count DISTINCT files: one file renamed 25
    // times is not a rename burst; one .locked file saved 10 times
    // is not a ransom-extension artifact.
    [Fact]
    public void F10_Families_CountDistinctFiles_NotRawEvents()
    {
        var d = new RansomwareDetector();
        var evs = new List<FileActivityEvent>();
        for (var i = 0; i < 25; i++)
            evs.Add(Ev(@"C:\data\same.dat", "renamed", 3.0, @"C:\data\prev.dat"));
        for (var i = 0; i < 10; i++)
            evs.Add(Ev(@"C:\data\one.locked", "modified", 3.0));
        d.Ingest(evs);
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Equal(1, v.RenameCount);
        Assert.Equal(1, v.RansomExtensionFiles);
        Assert.DoesNotContain(SignalFamilies.RenameBurst, v.FamiliesPresent);
        Assert.DoesNotContain(SignalFamilies.RansomArtifact, v.FamiliesPresent);
        Assert.False(v.ShouldIsolate);
    }

    // F11 — an unspent un-isolate envelope minted BEFORE the
    // current isolation episode began releases nothing, even
    // inside its expiry: release is bound to the episode.
    [Fact]
    public void F11_UnisolateEnvelope_MintedBeforeEpisode_Refused()
    {
        var rig = new Rmm17Tests.Rig();
        // Minted 5 min before the episode, expires 5 min after T0.
        var early = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes("{\"action\":\"rmm17.unisolate\",\"deviceId\":\"dev-1\"}"),
            T0.AddMinutes(-5), TimeSpan.FromMinutes(10));
        rig.Files.Enqueue(Burst());
        rig.Service.RunDetectionCycle(); // episode begins at T0
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        var (applied, detail) = rig.Service.HandleSignedUnisolate(early);
        Assert.False(applied, detail);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "endpoint_unisolate_refused" && e.Detail.Contains("predates the current isolation episode"));
    }

    // F12 — the detector window is capped, and the recording fakes
    // live in the TEST assembly (a DI mis-wiring in production
    // cannot substitute one).
    [Fact]
    public void F12_WindowCapped_AndFakesLiveInTestAssembly()
    {
        var d = new RansomwareDetector();
        d.Ingest(Enumerable.Range(0, RansomwareDetector.MaxWindowEvents + 5000)
            .Select(i => Ev($@"C:\d\f{i}.bin", "modified", 3.0)));
        Assert.True(d.WindowEventCount <= RansomwareDetector.MaxWindowEvents,
            $"window holds {d.WindowEventCount}");
        Assert.Equal(typeof(Rmm17Tests).Assembly, typeof(FakeNetworkControl).Assembly);
        Assert.Equal(typeof(Rmm17Tests).Assembly, typeof(FakeFileActivitySource).Assembly);
        Assert.Equal(typeof(Rmm17Tests).Assembly, typeof(FakeAvStatusSource).Assembly);
    }
}
