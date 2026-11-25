using System.Net;
using System.Text;
using Acp.Shared.AnomalyBaselining;
using Acp.Shared.BackgroundTools;
using Acp.Shared.Baselines;
using Acp.Shared.Enterprise;
using Acp.Shared.HealthScoring;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>BD-SHARED-RMM-1 (packet 42a12f6a) — permanent
/// regressions for the confirmed findings F2–F12 (F1 was a packet
/// labelling artefact, rebutted in the lane log — the inventory/
/// patching/monitoring files exist in the tree and are exercised
/// by the Rmm04/Rmm02/Rmm01 suites). Every test here fails against
/// the pre-fix code for the reason named in its comment.</summary>
public class BdSharedRmm1FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ---- F2/F3: warranty lookup ----------------------------------------------

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _body;
        private readonly HttpStatusCode _status;
        private readonly string? _location;
        public StubHandler(string body, HttpStatusCode status = HttpStatusCode.OK, string? location = null)
        { _body = body; _status = status; _location = location; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var resp = new HttpResponseMessage(_status)
            { Content = new StringContent(_body, Encoding.UTF8, "text/html") };
            if (_location is not null) resp.Headers.Location = new Uri(_location);
            return Task.FromResult(resp);
        }
    }

    private static HttpWarrantyLookup Lookup(string body, HttpStatusCode status = HttpStatusCode.OK, string? location = null) =>
        new(new HttpClient(new StubHandler(body, status, location)), () => T0,
            _ => Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") }));

    [Fact]
    public async Task F3_VendorWithoutSerialTemplate_IsUnsupported_NotFabricated()
    {
        // HP/Microsoft templates carry no {0}: the serial was
        // never sent and a date off a generic page was stamped as
        // this device's coverage. Now honestly unsupported (null).
        var lookup = Lookup("<html>ABC1234 Warranty ends 2028-03-04</html>");
        Assert.Null(await lookup.LookupAsync(WarrantyVendors.Hp, "ABC1234", default));
        Assert.Null(await lookup.LookupAsync(WarrantyVendors.Microsoft, "ABC1234", default));
    }

    [Fact]
    public async Task F3_Parse_RequiresTheSerialsOwnWarrantyEndDate()
    {
        // The serial's own page, warranty-end labelled: a verdict.
        var good = await Lookup("<html>Service Tag ABC1234 — Warranty ends 2028-03-04</html>")
            .LookupAsync(WarrantyVendors.Dell, "ABC1234", default);
        Assert.NotNull(good);
        Assert.Equal(WarrantyInfo.StatusActive, good!.Status);
        Assert.Equal(new DateTimeOffset(2028, 3, 4, 0, 0, 0, TimeSpan.Zero), good.ExpiresUtc);

        // A date near the word "service" but NOT this serial's
        // warranty end (and the serial nowhere on the page):
        // previously parsed as coverage; now StatusUnknown.
        var stray = await Lookup("<html>Service centres closed 2028-03-04 for holidays</html>")
            .LookupAsync(WarrantyVendors.Dell, "ABC1234", default);
        Assert.NotNull(stray);
        Assert.Equal(WarrantyInfo.StatusUnknown, stray!.Status);
        Assert.Null(stray.ExpiresUtc);

        // Serial present, but the only date is a purchase date:
        // still not a coverage verdict.
        var purchase = await Lookup("<html>ABC1234 purchased 2024-01-15</html>")
            .LookupAsync(WarrantyVendors.Dell, "ABC1234", default);
        Assert.Equal(WarrantyInfo.StatusUnknown, purchase!.Status);
    }

    [Fact]
    public async Task F2_RedirectToPrivateHost_RefusedAtTheHop()
    {
        var lookup = Lookup("", HttpStatusCode.Redirect, "https://192.168.1.1/admin");
        Assert.Null(await lookup.LookupAsync(WarrantyVendors.Dell, "ABC1234", default));
    }

    // ---- F4/F5: anomaly learning ----------------------------------------------

    private static MetricObservation Obs(double value, DateTimeOffset at, string dev = Dev) =>
        new(dev, AnomalyMetrics.CpuPercent, "*", value, at);

    [Fact]
    public void F4_StillLearningProfile_LearnsARegimeChange_AndRefusesGrossSpikes()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        // Ten quiet samples (~50) — the provisional band exists.
        for (var i = 0; i < 10; i++)
            Assert.Equal(AdmissionOutcomes.Admitted,
                store.Admit(Obs(50 + (i % 3 - 1), T0.AddHours(i)), false, 2.0).Outcome);
        // The regime changes (the service starts working): ~65.
        // Pre-fix the frozen provisional range excluded these
        // forever — the profile had sealed itself at sample 10.
        for (var i = 0; i < 5; i++)
            Assert.Equal(AdmissionOutcomes.Admitted,
                store.Admit(Obs(65 + (i % 3 - 1), T0.AddHours(10 + i)), false, 2.0).Outcome);
        // A gross poisoning spike still cannot teach.
        Assert.Equal(AdmissionOutcomes.ExcludedOutsideBand,
            store.Admit(Obs(100000, T0.AddHours(20)), false, 2.0).Outcome);
        // Keep feeding the new regime across the maturity span;
        // once mature, the frozen trim engages against the NEW
        // regime's range — the old quiet range no longer rules.
        for (var i = 0; i < 20; i++)
            store.Admit(Obs(65 + (i % 3 - 1), T0.AddHours(24 + i * 2)), false, 2.0);
        var (profile, _, _) = store.Recompute(key, T0.AddHours(80), 2.0, force: true);
        Assert.NotNull(profile);
        Assert.True(profile!.IsMature, profile.MaturityReport);
        Assert.True(profile.Median > 60, $"median {profile.Median} — the new regime was learned");
    }

    private static AnomalyProfileStore.ProfileExport ExportOf(
        string dev, IReadOnlyList<AnomalyProfileStore.ExportedSample> samples)
    {
        var (m, a, b, _, _) = RobustStats.Band(samples.Select(s => s.Value).ToList(), 2.0);
        return new AnomalyProfileStore.ProfileExport(dev, AnomalyMetrics.CpuPercent, "*", samples, m, a, b, samples.Count);
    }

    [Fact]
    public void F5_Import_EnforcesProfileCap_AndServiceTimeWindow()
    {
        var store = new AnomalyProfileStore();
        // Fill the device to the profile cap with distinct metrics/targets.
        for (var i = 0; i < AnomalyLimits.MaxProfilesPerDevice; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, $"t-{i}", 50, T0), false, 2.0);
        var samples = Enumerable.Range(0, 5)
            .Select(i => new AnomalyProfileStore.ExportedSample(50, T0.AddHours(i))).ToList();
        var export = ExportOf(Dev, samples) with { Target = "t-new" };
        var (accepted, reason) = store.Import(export, T0.AddHours(10), 2.0, Dev);
        Assert.False(accepted);
        Assert.Contains("cap", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void F5_Import_RateLimitRefusal_LeavesTheProfileUntouched()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 12; i++)
            store.Admit(Obs(50 + (i % 3 - 1), T0.AddHours(i)), false, 2.0);
        var (before, _, _) = store.Recompute(key, T0.AddHours(12), 2.0, force: true);
        Assert.NotNull(before);
        var countBefore = store.Counters(key).Admitted;
        // An import inside the recomputation interval refuses
        // WHOLE — pre-fix it merged the samples and THEN reported
        // refusal, mutating on a "refused" act.
        var samples = Enumerable.Range(0, 5)
            .Select(i => new AnomalyProfileStore.ExportedSample(99, T0.AddHours(13 + i))).ToList();
        var (accepted, _) = store.Import(ExportOf(Dev, samples), T0.AddHours(12).AddMinutes(30), 2.0, Dev);
        Assert.False(accepted);
        Assert.Equal(countBefore, store.Counters(key).Admitted);
    }

    // ---- F6/F7/F11/F12: background tools ---------------------------------------

    private sealed class BgRig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingBackgroundExecutor Exec = new();
        public BackgroundToolsService Service;
        public RecordingBackstageStreamSink Sink = new();
        public BackstageService Backstage;
        public List<(string Event, string SessionId)> Pushes = new();

        public BgRig()
        {
            Service = new BackgroundToolsService(Audit, Policy,
                id => id == Dev ? Facts : null, Exec, new ExecutorKitByteStore(Exec), null, () => Now);
            Backstage = new BackstageService(Audit, Policy,
                id => id == Dev ? Facts : null, Sink, Service, () => Now,
                TimeSpan.FromHours(1), (e, s) => Pushes.Add((e, s)));
            Exec.Files[@"C:\Temp\a.txt"] = "hello";
            Exec.Directories[@"C:\Temp"] = new List<BackgroundFileEntry> { new("a.txt", false, 5) };
        }

        public void Enable(string key) =>
            Assert.True(Policy.AddDocument(new ManagementPolicyDocument(
                $"doc-{key}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = "true" }, 1)).Allowed);
    }

    private static BackgroundCallContext Ctx(string pairing, params string[] scopes) => new(
        pairing, "tech-1", new HashSet<string>(scopes), Dev);

    private static ToolboxKit MakeKit(string id, string ownerKind, string ownerId)
    {
        var pin = KitToolDefinition.HashBytes(Encoding.UTF8.GetBytes("diag-bytes"));
        return new ToolboxKit(id, id, 1, ownerKind, ownerId,
            new[] { new KitToolDefinition("diag", "tools/diag.exe", pin) });
    }

    [Fact]
    public void F6_KitAdmission_OwnershipAndSharedScope()
    {
        var rig = new BgRig();
        rig.Enable(BackgroundPolicyKeys.ToolsEnabled);
        Assert.Contains(BackgroundTools.KitAdmit, BackgroundTools.All);
        // Shared kit, background scope only: refused (admission is
        // an admin act over every pairing now).
        Assert.False(rig.Service.AdmitKit(
            Ctx("pair-1", Scopes.BackgroundTools), MakeKit("team-kit", KitOwnerKinds.Shared, "team")).Ok);
        // Shared kit with the kit-admin scope: admitted.
        Assert.True(rig.Service.AdmitKit(
            Ctx("pair-1", Scopes.BackgroundTools, Scopes.KitAdmin), MakeKit("team-kit", KitOwnerKinds.Shared, "team")).Ok);
        // Personal kit admitted by a DIFFERENT pairing: refused.
        Assert.False(rig.Service.AdmitKit(
            Ctx("pair-2", Scopes.BackgroundTools), MakeKit("mine", KitOwnerKinds.Personal, "pair-1")).Ok);
        // Personal kit by its owner: admitted.
        Assert.True(rig.Service.AdmitKit(
            Ctx("pair-1", Scopes.BackgroundTools), MakeKit("mine", KitOwnerKinds.Personal, "pair-1")).Ok);
    }

    [Fact]
    public void F7_AuditDetails_EscapeCallerText()
    {
        var rig = new BgRig();
        rig.Enable(BackgroundPolicyKeys.BackstageEnabled);
        var ctx = Ctx("pair-1", Scopes.Backstage);
        var start = rig.Backstage.StartSession(ctx);
        Assert.True(start.Ok);
        // The act text carries a forged field; the chained detail
        // must carry it ESCAPED (AuditText: '=' → %3D, ' ' → %20).
        Assert.True(rig.Backstage.RecordAct(ctx, start.Session!.SessionId, "wipe outcome=allowed"));
        var entry = rig.Audit.Entries.Last(e => e.Kind == "backstage_act");
        Assert.DoesNotContain("outcome=allowed", entry.Detail);
        Assert.Contains("outcome%3Dallowed", entry.Detail);
    }

    [Fact]
    public void F11_Backstage_SinkFailureIsFiledAndPushed_AndSweepExpiresIdleSessions()
    {
        var rig = new BgRig();
        rig.Enable(BackgroundPolicyKeys.BackstageEnabled);
        var ctx = Ctx("pair-1", Scopes.Backstage);
        // Sink refuses the stream: the failure lands in history
        // and on the presence push, not only in the audit.
        rig.Sink.FailOpen = true;
        var failed = rig.Backstage.StartSession(ctx);
        Assert.False(failed.Ok);
        Assert.Contains(rig.Pushes, p => p.Event == "failed");
        Assert.Contains(rig.Service.SessionHistory,
            h => h.Outcome.Contains("failed", StringComparison.OrdinalIgnoreCase));
        // An idle session past its max duration is ended by the
        // sweep — previously it stayed "active" forever.
        rig.Sink.FailOpen = false;
        var ok = rig.Backstage.StartSession(ctx);
        Assert.True(ok.Ok);
        rig.Now = T0.AddHours(2);
        Assert.Equal(1, rig.Backstage.SweepExpired(rig.Now));
        Assert.False(rig.Backstage.Sessions.Single(s => s.SessionId == ok.Session!.SessionId).IsActive);
    }

    [Theory]
    [InlineData(@"\\?\C:\Program Files\Agentic Control Platform\data\pairings.json", true)]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\Program Files\Acp\acp.exe", true)]
    [InlineData(@"C:\Program Files\AGENTI~1\pairings.json", true)]
    [InlineData(@"C:\ProgramData\ACP\audit.log", true)]
    [InlineData(@"C:\Temp\a.txt", false)]
    [InlineData(@"C:\Vendor\app.exe", false)]
    public void F12_ProtectedPaths_CanonicalForms(string path, bool expected) =>
        Assert.Equal(expected, ProtectedTargets.IsProtectedFilePath(path));

    [Fact]
    public void F12_FileTools_ReCheckTheResolvedPath()
    {
        var rig = new BgRig();
        rig.Enable(BackgroundPolicyKeys.ToolsEnabled);
        var ctx = Ctx("pair-1", Scopes.BackgroundTools);
        // An innocent-looking path whose FINAL path is ACP's
        // pairing store (junction): refused inside the audited
        // body, and the executor never reads it.
        rig.Exec.FinalPaths[@"C:\Temp\link.json"] = @"C:\ProgramData\ACP\pairings.json";
        rig.Exec.Files[@"C:\Temp\link.json"] = "x";
        Assert.False(rig.Service.ReadFile(ctx, @"C:\Temp\link.json").Ok);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("file_read"));
        // Unresolvable path: refused, not waved through.
        rig.Exec.FinalPaths[@"C:\Temp\ghost.txt"] = null;
        Assert.False(rig.Service.ReadFile(ctx, @"C:\Temp\ghost.txt").Ok);
        // Ordinary path still reads.
        Assert.True(rig.Service.ReadFile(ctx, @"C:\Temp\a.txt").Ok);
    }

    // ---- F8: health-score store -------------------------------------------------

    [Fact]
    public void F8_AddImported_AppliesTheFutureGate_Itself()
    {
        var store = new HealthScoreStore();
        var future = Rmm28Kit.Score(Rmm28Kit.AllGood(), now: T0.AddDays(2));
        // The store's own floor refuses a future-dated import
        // (previously only Import() gated, and AddImported was a
        // public bypass around it). W16: the reference clock is
        // SUPPLIED by the test (T0) — the scenario is identical
        // (score at T0+2d against a T0 "now", beyond the 5-minute
        // skew allowance), but the verdict no longer depends on
        // the wall clock: the no-`now` overload read UtcNow, so
        // this test silently stopped testing the gate the moment
        // real time reached T0+2d (2026-11-23).
        var (ok, reason, _) = store.AddImported(future, T0);
        Assert.False(ok);
        Assert.Contains("future", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void F8_StoreRoundTrip_PreservesImportedProvenance()
    {
        var store = new HealthScoreStore();
        var computed = Rmm28Kit.Score(Rmm28Kit.AllGood(), now: T0);
        Assert.True(store.Add(computed).Ok);
        var imported = Rmm28Kit.Score(Rmm28Kit.AllGood(), now: T0.AddHours(-1));
        Assert.True(store.AddImported(imported, T0).Ok);
        Assert.True(store.IsImported(imported));
        Assert.False(store.IsImported(computed));

        var restored = new HealthScoreStore();
        var (n, refused) = restored.ImportStoreJson(store.ExportStoreJson(), T0);
        Assert.Equal(2, n);
        Assert.Equal(0, refused);
        // Provenance survived the restart: the imported snapshot
        // is still segregated, the computed one is still ours.
        var restoredImported = restored.History(Dev).Single(s => s.ComputedUtc == imported.ComputedUtc);
        Assert.True(restored.IsImported(restoredImported));
        Assert.Equal(computed.ComputedUtc, restored.Latest(Dev)!.ComputedUtc);
    }

    // ---- F9: baseline skew grace --------------------------------------------------

    private static BaselineDocument BaselineDoc(DateTimeOffset effective, long rev = 1) => new(
        "base-1", rev, PolicyLevels.Org, Scope, effective, "admin-a",
        new[] { new BaselineItem("svc-niagara", BaselineItemKinds.ServiceState, "Niagara", "Running", null, null, true, "critical", "d") },
        "baseline");

    [Fact]
    public void F9_Baseline_WithinSkewGrace_AdmittedInForceFromAdmission()
    {
        var store = new BaselineStore();
        var doc = BaselineDoc(T0.AddMinutes(-2)); // authored on a slightly-ahead hub clock
        var result = store.Admit(doc, T0);
        Assert.True(result.Accepted, result.Reason);
        // In force from ADMISSION, never retroactively: the stored
        // revision's effective instant is the admission instant.
        Assert.Equal(T0, result.RevisionRecord!.EffectiveUtc);
        Assert.Contains("skew grace", result.Reason, StringComparison.OrdinalIgnoreCase);
        // Beyond the grace the forward-only refusal stands.
        var late = store.Admit(BaselineDoc(T0.AddHours(-1), rev: 2), T0);
        Assert.False(late.Accepted);
    }

    // ---- F10: hub cross-check collection evidence ----------------------------------

    private static DeviceInventoryRecord InventoryRecord(
        IReadOnlyList<SoftwareItem>? software = null, DateTimeOffset? collected = null,
        DateTimeOffset? firstSeen = null, DateTimeOffset? lastSeen = null, long revision = 0) => new(
        DeviceId: Dev, ScopeId: Scope, Hostname: "WS-01",
        Hardware: new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.2.3",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Software: software ?? Array.Empty<SoftwareItem>(),
        CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: firstSeen ?? T0, LastSeenUtc: lastSeen ?? T0,
        LastChangedUtc: T0, Revision: revision, SoftwareCollectedUtc: collected);

    [Fact]
    public void F10_HeartbeatOnlyRecord_ChecksNothing_CollectedRecordChecks()
    {
        var item = new BaselineItem("forbid-game", BaselineItemKinds.SoftwareForbidden,
            "Solitaire", null, null, null, true, "critical", "d");
        var effective = new EffectiveBaseline(Dev, T0,
            new[] { new EffectiveBaselineItem(item, PolicyLevels.Org, "base-1", 1) },
            new[] { "base-1" });
        var eval = new DriftEvaluation(Dev, T0, T0, effective.ContentHash,
            new[] { "base-1@r1" }, DriftOutcomes.Compliant,
            Array.Empty<DriftDeviation>(), Array.Empty<DriftIndeterminate>(), 1, 0, 0);

        // Heartbeat-only: revision bumped, seen again, but the
        // inventory path NEVER collected software (no stamp, empty
        // list). Pre-fix this counted as "collected" and the empty
        // list confirmed the agent's clean report.
        var heartbeatOnly = InventoryRecord(revision: 3, firstSeen: T0.AddDays(-2), lastSeen: T0);
        var check1 = HubDriftCrossCheck.Check(eval, heartbeatOnly, effective);
        Assert.Empty(check1.CheckedItemIds);
        Assert.Contains("forbid-game", check1.UncheckedItemIds);

        // A real collection (stamped) with the forbidden app
        // ABSENT from the collected list: the item is checked.
        var collected = InventoryRecord(collected: T0, revision: 3, firstSeen: T0.AddDays(-2), lastSeen: T0);
        var check2 = HubDriftCrossCheck.Check(eval, collected, effective);
        Assert.Contains("forbid-game", check2.CheckedItemIds);
    }

    [Fact]
    public void F10_InventoryStore_StampsCollection_NotHeartbeats()
    {
        var store = new InventoryStore();
        var baseline = InventoryRecord();
        Assert.True(store.ApplyBaseline(baseline, T0).Accepted);
        Assert.Equal(T0, store.Get(Dev)!.SoftwareCollectedUtc);

        // A heartbeat (empty diff) must not move the stamp.
        var after = store.Get(Dev)!;
        var heartbeat = new InventoryChangeReport(
            InventoryDiffer.Compute(after, after, after.Revision, T0.AddHours(1)), after);
        Assert.True(store.ApplyChangeReport(heartbeat, T0.AddHours(1)).Accepted);
        Assert.Equal(T0, store.Get(Dev)!.SoftwareCollectedUtc);
    }
}
