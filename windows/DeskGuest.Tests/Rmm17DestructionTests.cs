using System.Text;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-17 DESTRUCTION PASS — hostile attempts against the isolation
// bar, the release path, the channel exemption, the AV status
// truth, and policy. Each test is an attack that must FAIL to break
// the directive; breaks found during the pass became fixes +
// regression tests here (see ledger-rmm17.md).
public class Rmm17DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    private static FileActivityEvent Ev(string path, string kind = "modified",
        double? entropy = null, string? old = null, string proc = "evil.exe") =>
        new(path, kind, old, entropy, proc, T0);

    private static List<FileActivityEvent> Burst(string proc)
    {
        var list = new List<FileActivityEvent>();
        for (var i = 0; i < 30; i++)
            list.Add(Ev($@"C:\Users\j\doc{i}.locked", "renamed", 7.9, $@"C:\Users\j\doc{i}.docx", proc));
        for (var i = 30; i < 60; i++)
            list.Add(Ev($@"C:\Users\j\file{i}.dat", "modified", 7.8, null, proc));
        list.Add(Ev(@"C:\Users\j\README_DECRYPT.txt", "created", 4.0, null, proc));
        return list;
    }

    // ATTACK 1 — false-positive engineering: ordinary bulk activity
    // must NOT isolate. A legit backup (mass sequential writes), a
    // photo import at REAL JPEG entropy, a compressing backup that
    // renames 300 files into archives, a build (mass writes of
    // obj/bin, renames of temp files). None carries a ransom
    // artifact, so none can meet the bar (D38-F1) — behaviour alone
    // (mass + rename + entropy) is exactly what these tools do.
    [Fact]
    public void Attack_LegitBulkActivity_DoesNotIsolate()
    {
        // Backup: 500 file copies, ordinary entropy, no renames.
        var backup = new RansomwareDetector();
        backup.Ingest(Enumerable.Range(0, 500).Select(i =>
            Ev($@"D:\Backup\file{i}.docx", "created", 4.5, null, "backup-agent.exe")));
        Assert.False(backup.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);

        // Photo import: 300 creates with camera extensions at REAL
        // JPEG entropy (~7.9 bits/byte — D38-F1: the original test
        // used 6.8, below the floor, which proved nothing).
        // Inherently-compressed formats never count toward entropy.
        var photos = new RansomwareDetector();
        photos.Ingest(Enumerable.Range(0, 300).Select(i =>
            Ev($@"C:\Users\j\Pictures\IMG_{i}.jpg", "created", 7.9, null, "photos.exe")));
        var pv = photos.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Equal(0, pv.HighEntropyFiles);
        Assert.False(pv.ShouldIsolate, pv.Detail);

        // Compressing backup (D38-F1): renames AND compresses 300
        // files — mass + rename at high entropy, NO ransom artifact.
        // The original test dodged this shape with plain copies;
        // archive extensions are inherently compressed, so entropy
        // does not count, and without an artifact the bar cannot be
        // met however many families behaviour alone suggests.
        var arc = new RansomwareDetector();
        arc.Ingest(Enumerable.Range(0, 300).Select(i =>
            Ev($@"D:\Backup\arc{i}.zip", "renamed", 7.9, $@"C:\data\doc{i}.docx", "backup-agent.exe")));
        var av = arc.Evaluate(RansomwareThresholds.Default, T0);
        Assert.False(av.ShouldIsolate, av.Detail);
        Assert.DoesNotContain(SignalFamilies.RansomArtifact, av.FamiliesPresent);

        // Build: 200 writes + 40 temp renames, low entropy, no artifacts.
        var build = new RansomwareDetector();
        var evs = new List<FileActivityEvent>();
        for (var i = 0; i < 200; i++) evs.Add(Ev($@"C:\src\obj\f{i}.dll", "modified", 5.0, null, "MSBuild.exe"));
        for (var i = 0; i < 40; i++) evs.Add(Ev($@"C:\src\obj\t{i}.tmp", "renamed", 5.0, $@"C:\src\obj\u{i}.tmp", "MSBuild.exe"));
        build.Ingest(evs);
        var v = build.Evaluate(RansomwareThresholds.Default, T0);
        Assert.False(v.ShouldIsolate, v.Detail);
    }

    // ATTACK 2 — slow-drip ransomware: stay under every threshold
    // inside any single window by encrypting slowly. HONEST
    // RESIDUAL (named, not fixed): a purely windowed heuristic
    // cannot see an attacker who encrypts 49 files/minute forever.
    // What the test proves is the boundary is exactly where the
    // design says it is — 49 files + full other signals still does
    // not isolate (mass is a REQUIRED family), and the verdict
    // detail shows the near-miss numbers for the record.
    [Fact]
    public void Attack_SlowDrip_StaysUnderBar_NamedResidual_BoundaryExact()
    {
        var d = new RansomwareDetector();
        // 24 renames + 24 modified + the note file itself = 49
        // distinct touched files (the note counts as a touched file).
        var evs = new List<FileActivityEvent>();
        for (var i = 0; i < 24; i++)
            evs.Add(Ev($@"C:\Users\j\doc{i}.locked", "renamed", 7.9, $@"C:\Users\j\doc{i}.docx"));
        for (var i = 24; i < 48; i++)
            evs.Add(Ev($@"C:\Users\j\file{i}.dat", "modified", 7.8));
        evs.Add(Ev(@"C:\Users\j\README_DECRYPT.txt", "created", 4.0));
        d.Ingest(evs);
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.Equal(49, v.DistinctFiles);
        Assert.False(v.ShouldIsolate, "slow-drip residual: mass family is required and 49 < 50");
        // One more file crosses the stated bar exactly.
        d.Ingest(new[] { Ev(@"C:\Users\j\file49.dat", "modified", 7.8) });
        Assert.True(d.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);
    }

    // ATTACK 3 — process-name spoofing: ransomware running AS
    // "backup-agent.exe" gets no exemption. Attribution is never an
    // allowlist in this design, so the spoof changes nothing.
    [Fact]
    public void Attack_ProcessNameSpoof_BackupName_EarnsNoExemption()
    {
        var d = new RansomwareDetector();
        d.Ingest(Burst("backup-agent.exe"));
        Assert.True(d.Evaluate(RansomwareThresholds.Default, T0).ShouldIsolate);
    }

    // ATTACK 4 — canary games: touching ONLY the canary (a curious
    // user, an indexer) must not isolate by itself; the canary is
    // one ingredient of one family, and the bar still applies.
    [Fact]
    public void Attack_CanaryTouchAlone_DoesNotIsolate()
    {
        var d = new RansomwareDetector(new[] { @"C:\canary\canary-doc.docx" });
        d.Ingest(new[] { Ev(@"C:\canary\canary-doc.docx", "modified", 4.0, null, "explorer.exe") });
        var v = d.Evaluate(RansomwareThresholds.Default, T0);
        Assert.True(v.CanaryTouched);
        Assert.False(v.ShouldIsolate);
    }

    // ATTACK 5 — isolation escape: every local release shape
    // refuses. Direct manager call, repeated calls, calls while
    // isolation_failed — none release. Only the signed path does
    // (proven in Rmm17Tests).
    [Fact]
    public void Attack_LocalUnisolate_EveryShape_Refuses()
    {
        var audit = new ChainedAuditLog();
        var net = new FakeNetworkControl();
        var mgr = new EndpointIsolationManager(Dev, net, audit);
        Assert.True(mgr.Isolate(Rmm17Tests.Rig.DefaultPlan(), "test", T0).Applied);
        for (var i = 0; i < 3; i++)
            Assert.False(mgr.TryLocalUnisolate($"attacker-{i}", T0).Applied);
        Assert.True(mgr.Status.IsIsolated);
        Assert.True(net.IsIsolationApplied);
        Assert.Equal(3, audit.Entries.Count(e => e.Kind == "endpoint_unisolate_refused_local"));
    }

    // ATTACK 6 — replayed un-isolate: the same signed envelope
    // presented twice. The RMM-03 nonce guard refuses the replay;
    // after a LEGITIMATE release + a NEW isolation episode, the old
    // envelope must not release the new episode.
    [Fact]
    public void Attack_ReplayedUnisolateEnvelope_RefusedForNewEpisode()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        rig.Service.RunDetectionCycle();
        var env = rig.UnisolateEnvelope();
        Assert.True(rig.Service.HandleSignedUnisolate(env).Applied);
        // New episode.
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        rig.Service.RunDetectionCycle();
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
        Assert.False(rig.Service.HandleSignedUnisolate(env).Applied); // replay
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // ATTACK 7 — exemption widening: try to smuggle general traffic
    // through the DeskGuest exemption. Wrong port on the hub host, the
    // hub host over a file-sharing port, an arbitrary host on the
    // exempt port — the matcher is exact host+port per exemption
    // for EVERY kind. (D38-F3: the LAN rung previously matched ANY
    // host on its port — the ransomware lateral-movement shape.
    // The rung now names its exact peer host like every other
    // exemption; a foreign LAN host on the rung port is refused,
    // asserted below.)
    [Fact]
    public void Attack_ExemptionWidening_ExactMatchOnly()
    {
        var plan = Rmm17Tests.Rig.DefaultPlan();
        Assert.False(plan.IsTrafficAllowed("hub.deskguest.local", 22));
        Assert.False(plan.IsTrafficAllowed("hub.deskguest.local", 445));
        Assert.False(plan.IsTrafficAllowed("attacker.local", 8443));
        Assert.False(plan.IsTrafficAllowed("100.64.0.99", 8443)); // tailnet neighbour, not the hub
        Assert.False(plan.IsTrafficAllowed(null, 8443));
        Assert.False(plan.IsTrafficAllowed("", 8443));
        Assert.True(plan.IsTrafficAllowed("HUB.DeskGuest.LOCAL", 8443)); // case-insensitive host is fine
        // D38-F3: the rung port admits ONLY its exact peer host.
        Assert.True(plan.IsTrafficAllowed("hub.deskguest.local", 40117));
        Assert.False(plan.IsTrafficAllowed("192.168.1.50", 40117));
        Assert.False(plan.IsTrafficAllowed("attacker.local", 40117));
        Assert.False(plan.IsTrafficAllowed(null, 40117));
    }

    // ATTACK 8 — isolation that kills DeskGuest: a plan whose exemptions
    // omit the channel, or actuation that silently no-ops. Empty
    // plan refuses (Rmm17Tests); here: actuation failure must read
    // isolation_failed with the CRITICAL alert STILL raised, and a
    // retry on the next cycle must be able to succeed.
    [Fact]
    public void Attack_ActuationFailure_ReadsFailed_AlertStillRaised_RetryWorks()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Net.ThrowOnApply = true;
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        var r = rig.Service.RunDetectionCycle();
        Assert.False(r.IsolationApplied);
        Assert.Equal(IsolationStates.IsolationFailed, rig.Isolation.Status.State);
        Assert.Single(rig.Centre.ActiveAlerts); // the critical alert went out anyway
        rig.Net.ThrowOnApply = false;
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        var r2 = rig.Service.RunDetectionCycle();
        Assert.True(r2.IsolationApplied);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // ATTACK 9 — AV status lying: a product claiming "healthy"
    // through a dead source, and through a stale observation, reads
    // STALE both times. A product claiming healthy with fresh
    // observation but ancient definitions also reads stale.
    [Fact]
    public void Attack_AvStatusLying_DeadOrStaleSource_ReadsStaleNotHealthy()
    {
        var policy = EndpointSecurityPolicy.Default;
        AvStatusReading Lying(bool alive, DateTimeOffset observed, DateTimeOffset? defs = null) => new(
            "defender", true, true, true, defs ?? T0.AddHours(-1), T0.AddDays(-1),
            observed, alive, "healthy");

        var dead = AvPostureEvaluator.Evaluate(Dev, new[] { Lying(false, T0) }, policy, T0);
        Assert.Contains(dead.Findings, f => f.State == AvPostureStates.Stale);
        Assert.DoesNotContain(dead.Findings, f => f.State == AvPostureStates.Protected);

        var staleObs = AvPostureEvaluator.Evaluate(Dev,
            new[] { Lying(true, T0.AddHours(-3)) }, policy, T0);
        Assert.Contains(staleObs.Findings, f => f.State == AvPostureStates.Stale);

        var staleDefs = AvPostureEvaluator.Evaluate(Dev,
            new[] { Lying(true, T0, T0.AddDays(-90)) }, policy, T0);
        Assert.Contains(staleDefs.Findings, f => f.State == AvPostureStates.Stale);
    }

    // ATTACK 10 — alert suppression games: a maintenance window
    // over the device must NEVER suppress the AV-off alerts (they
    // ride RMM-01's never-suppressible kind) NOR the ransomware
    // alert (ransomware_isolation joined NeverSuppressible in the
    // RES-3 closing integration — D38-F6: the packet's contradiction
    // is settled in the code's favour by ConditionKinds +
    // IntegrationTests). The isolation, the audit and the banner
    // are likewise untouched by any window.
    [Fact]
    public void Attack_MaintenanceWindow_CannotMuteAvOff_IsolationSurvivesAlertSuppression()
    {
        var rig = new Rmm17Tests.Rig();
        var (ok, _) = rig.Centre.AddWindow(new MaintenanceWindow(
            "w1", Dev, T0.AddMinutes(-1), T0.AddHours(2), "planned work", "admin", T0), T0);
        Assert.True(ok);
        // AV off under the window: still raised.
        rig.Av.Set(new AvStatusReading("defender", true, false, false,
            T0.AddHours(-1), T0.AddDays(-1), T0, true, "disabled"));
        rig.Service.RefreshAvPosture();
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.SecurityAvOff);
        // Ransomware under the window: isolated anyway — and, since
        // the RES-3 closing-integration change (2026-11-21) added
        // ransomware_isolation to RMM-01's NeverSuppressible set, the
        // alert itself is NO LONGER suppressed either (supersedes
        // this test's original suppressed-outcome expectation).
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        var r = rig.Service.RunDetectionCycle();
        Assert.True(r.IsolationApplied);
        Assert.Equal(RaiseOutcome.New, r.AlertOutcome);
        Assert.False(string.IsNullOrWhiteSpace(rig.Isolation.Status.BannerText));
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == "ransomware_isolation");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_isolated");
    }

    // ATTACK 11 — policy weakening: an attacker (or a careless
    // admin) pushes policy that guts the detector — 1 family, 1
    // file, giant staleness bounds. Floors clamp every value; the
    // clamps are audited; the burst still isolates at the FLOOR bar.
    [Fact]
    public void Attack_PolicyWeakening_FloorsHold_AndAreAudited()
    {
        var rig = new Rmm17Tests.Rig();
        rig.SetPolicy(EndpointSecurityPolicyKeys.MinSignalFamilies, "1");
        rig.SetPolicy(EndpointSecurityPolicyKeys.MassFileThreshold, "1");
        var p = rig.Service.CurrentPolicy(T0);
        Assert.Equal(3, p.Thresholds.MinSignalFamilies);
        Assert.Equal(50, p.Thresholds.MassFileThreshold);
        // A single-family event still does not isolate at the floor bar.
        rig.Files.Enqueue(Enumerable.Range(0, 60)
            .Select(i => Ev($@"C:\d\f{i}.bin", "modified", 3.0)).ToArray());
        Assert.False(rig.Service.RunDetectionCycle().IsolationApplied);
    }

    // ATTACK 12 — tampered un-isolate payload: flip one byte of a
    // signed envelope's payload (device id) after signing. The
    // RMM-03 hash check refuses before the manager ever sees it.
    [Fact]
    public void Attack_TamperedUnisolatePayload_Refused()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        rig.Service.RunDetectionCycle();
        var env = rig.UnisolateEnvelope();
        var payload = Convert.FromBase64String(env.PayloadBase64);
        payload[10] ^= 0xFF;
        var tampered = env with { PayloadBase64 = Convert.ToBase64String(payload) };
        Assert.False(rig.Service.HandleSignedUnisolate(tampered).Applied);
        Assert.Equal(IsolationStates.Isolated, rig.Isolation.Status.State);
    }

    // ATTACK 13 — detector reset discipline: after a signed
    // release, the SAME windowed activity must not instantly
    // re-isolate (the manager's release resets the detector via
    // the service); fresh activity must earn the bar again.
    [Fact]
    public void Attack_PostRelease_StaleWindowDoesNotReisolate()
    {
        var rig = new Rmm17Tests.Rig();
        rig.Files.Enqueue(Burst("evil.exe").ToArray());
        rig.Service.RunDetectionCycle();
        Assert.True(rig.Service.HandleSignedUnisolate(rig.UnisolateEnvelope()).Applied);
        var r = rig.Service.RunDetectionCycle(); // no new activity
        Assert.False(r.IsolationApplied);
        Assert.Equal(IsolationStates.Normal, rig.Isolation.Status.State);
    }
}
