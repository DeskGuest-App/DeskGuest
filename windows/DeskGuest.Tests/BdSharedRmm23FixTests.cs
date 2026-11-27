using System.Globalization;
using System.Net;
using System.Text;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.Runbooks;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.SoftwareMetering;
using DeskGuest.Shared.WorkItems;
using Xunit;

namespace DeskGuest.Tests;

// =====================================================================
// BD-SHARED-RMM-2 + BD-SHARED-RMM-3 — permanent regression tests for
// the Wave 2 Lane B fixes (2026-11-22). Each test names the finding
// it pins. Findings dispositioned REBUTTED / ALREADY-PRESENT in the
// lane report (rmm-2 F4/F5/F6, rmm-3 F1) have no test here because
// no product code changed for them.
// =====================================================================
public class BdSharedRmm23FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";

    // ---- rmm-2 F1: pinned payload / pinned version ------------------

    [Fact]
    public void F1_WindowsThirdParty_MsiPayload_InstallsFromLocalPayload()
    {
        var win = new WindowsPatchApplier();
        var r = win.BuildApply(new PatchApplyRequest(Rmm02Tests.ThirdParty(), "/tmp/app.msi", "dev1"));
        Assert.True(r.Ok, r.Detail);
        Assert.Equal("msiexec.exe", r.InstallPlan!.Executable);
        Assert.Contains("/tmp/app.msi", r.InstallPlan.Arguments);
        // verify lists versions so the host compares, not just sees:
        Assert.Contains("--versions", r.VerifyPlan!.Arguments);
    }

    [Fact]
    public void F1_WindowsThirdParty_NoInstallerPayload_WingetPinnedToFixedVersion()
    {
        var win = new WindowsPatchApplier();
        var r = win.BuildApply(new PatchApplyRequest(Rmm02Tests.ThirdParty(), "/tmp/p.bin", "dev1"));
        Assert.True(r.Ok, r.Detail);
        Assert.Equal("winget", r.InstallPlan!.Executable);
        Assert.Contains("install", r.InstallPlan.Arguments);
        Assert.DoesNotContain("upgrade", r.InstallPlan.Arguments);
        var vi = r.InstallPlan.Arguments.ToList().IndexOf("--version");
        Assert.True(vi >= 0 && r.InstallPlan.Arguments[vi + 1] == "2.0");
    }

    [Fact]
    public void F1_LinuxThirdParty_DebPayload_InstallsFromLocalFile()
    {
        var linux = new LinuxPatchApplier();
        var entry = Rmm02Tests.ThirdParty() with { TargetOs = "linux" };
        var r = linux.BuildApply(new PatchApplyRequest(entry, "/tmp/x.deb", "dev1"));
        Assert.True(r.Ok, r.Detail);
        Assert.Equal("apt-get", r.InstallPlan!.Executable);
        Assert.Contains("/tmp/x.deb", r.InstallPlan.Arguments);
        Assert.DoesNotContain("Contoso.App=2.0", r.InstallPlan.Arguments);
    }

    // ---- rmm-2 F2: WAL failure refuses the step ----------------------

    [Fact]
    public void F2_BeginStep_WalFailure_RefusesAndRollsBack()
    {
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-w2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // Persistence path whose parent is a FILE: every WAL
            // append fails with an IO error.
            var blocker = Path.Combine(dir, "blocker");
            File.WriteAllText(blocker, "x");
            var j = new JobJournal();
            j.AttachPersistence(Path.Combine(blocker, "journal.json"));
            var job = j.CreateJob(JobKinds.FileTransfer, "dev1",
                new[] { new JobStepDefinition("s1", "s1", StepIdempotency.NonIdempotent) }, null, T0);
            Assert.Null(job); // genesis entry could not be made durable
            Assert.NotNull(j.PersistenceError);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void F2_BeginStep_WalFailureAfterAttach_StepNeverRuns()
    {
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-w2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var j = new JobJournal();
            var job = j.CreateJob(JobKinds.FileTransfer, "dev1",
                new[] { new JobStepDefinition("s1", "s1", StepIdempotency.NonIdempotent) }, null, T0)!;
            Assert.True(j.StartJob(job.Id, T0));
            // Break persistence AFTER the job exists: point the WAL at
            // a path under a file.
            var blocker = Path.Combine(dir, "blocker");
            File.WriteAllText(blocker, "x");
            j.AttachPersistence(Path.Combine(blocker, "journal.json"));
            Assert.False(j.BeginStep(job.Id, "s1", T0));
            Assert.NotNull(j.PersistenceError);
            // State rolled back: the step is still pending, so replay
            // can never see it as running.
            Assert.Equal(StepStates.Pending, j.GetJob(job.Id)!.Steps[0].State);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // ---- rmm-2 F3: save/anchor snapshot consistency ------------------

    [Fact]
    public void F3_SaveUnderConcurrentAppends_LoadsWithIntactChain()
    {
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-w2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "journal.json");
            var j = new JobJournal();
            var job = j.CreateJob(JobKinds.FileTransfer, "dev1",
                Enumerable.Range(1, 40).Select(i => new JobStepDefinition($"s{i}", $"s{i}", StepIdempotency.Idempotent)).ToList(),
                null, T0)!;
            j.StartJob(job.Id, T0);
            var saver = Task.Run(() => { for (var i = 0; i < 30; i++) j.SaveToFile(path); });
            for (var i = 1; i <= 40; i++) { j.BeginStep(job.Id, $"s{i}", T0); j.CompleteStep(job.Id, $"s{i}", T0); }
            saver.Wait();
            j.SaveToFile(path);
            var loaded = new JobJournal();
            var v = loaded.LoadFromFile(path);
            Assert.True(v.Ok, v.Summary);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // ---- rmm-2 F7: scanner matches targeting semantics ----------------

    [Fact]
    public void F7_DetermineMissing_SideBySideInstalls_ReportsLowestVersion()
    {
        var record = Rmm02Tests.Record("dev1", "Windows 11 Pro", "22631.1",
            new[] { ("Contoso App", "2.0"), ("Contoso App", "1.0") });
        var catalogue = new PatchCatalogue();
        Assert.True(catalogue.AddOrReplace(Rmm02Tests.ThirdParty()).Accepted);
        var missing = PatchScanner.DetermineMissing(record, catalogue);
        var m = Assert.Single(missing);
        Assert.Equal("1.0", m.InstalledVersion); // the vulnerable copy, not the first match
    }

    // ---- rmm-2 F8: remediation is a journal kind -----------------------

    [Fact]
    public void F8_RemediationKind_ExistsAndBindsAutomationClass()
    {
        Assert.True(JobKinds.IsKnown(JobKinds.Remediation));
        Assert.Equal(SignedCommandClasses.Automation, JobKinds.SignedClassByKind[JobKinds.Remediation]);
    }

    // ---- rmm-2 F9: clear_path canonicalisation --------------------------

    private static string? ValidateClear(string target, string? argument = null) =>
        new AutomationLibrary("lib", 1, new[]
        {
            AutomationDefinition.Create("a1", "a1", new[]
            {
                RemediationStep.Create("s1", RemediationStepKinds.ClearPath, target: target, argument: argument),
            }),
        }).Validate();

    [Theory]
    [InlineData(@"%SystemRoot%")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"C:\Windows\.")]
    [InlineData(@"C:\Windows\System32\..")]
    [InlineData(@"C:\Users")]
    [InlineData(@"C:\Program Files")]
    [InlineData(@"\\server\share\temp")]
    public void F9_ClearPath_ProtectedForms_Refused(string target) =>
        Assert.NotNull(ValidateClear(target));

    [Theory]
    [InlineData(@"%TEMP%")]
    [InlineData(@"C:\Windows\Temp")]
    [InlineData(@"C:\Users\User\AppData\Local\Temp")]
    public void F9_ClearPath_LegitimateTargets_Admitted(string target) =>
        Assert.Null(ValidateClear(target));

    [Fact]
    public void F9_ClearPath_BadAgeArgument_Refused() =>
        Assert.NotNull(ValidateClear(@"%TEMP%", argument: "not-a-number"));

    // ---- rmm-2 F10: signed flag + journal_untrusted ----------------------

    [Fact]
    public void F10_BrokenReport_RecordedAsJournalUntrusted_NotSilentlyDropped()
    {
        var rec = new JobStateReconciler(() => T0);
        var report = new JobStateReport("dev1", T0, true, "head",
            Array.Empty<JobStateSummary>(), ChainOk: false, BrokenAtSeq: 4,
            ChainSummary: "hash mismatch", JournalSeq: 9);
        var (accepted, _) = rec.Accept(report);
        Assert.False(accepted);
        Assert.True(rec.UntrustedDevices.ContainsKey("dev1"));
        Assert.Contains("journal_tampered", rec.UntrustedDevices["dev1"].Reason);
    }

    [Fact]
    public void F10_RequireSigned_RefusesUnsignedReport()
    {
        var rec = new JobStateReconciler(() => T0, requireSigned: true);
        var report = new JobStateReport("dev1", T0, true, "head",
            Array.Empty<JobStateSummary>(), ChainOk: true, JournalSeq: 1, Signed: false);
        Assert.False(rec.Accept(report).Accepted);
    }

    [Fact]
    public void F10_UnsignedJournal_ReportSaysUnsigned()
    {
        var j = new JobJournal();
        var report = j.BuildStateReport("dev1", true, T0);
        Assert.False(report.Signed);
        Assert.Equal(0, report.JournalSeq);
    }

    // ---- rmm-2 F11: latest decision governs -------------------------------

    [Fact]
    public void F11_FleetRejectAfterDeviceApproval_Governs()
    {
        var store = new PatchApprovalStore();
        var entry = Rmm02Tests.ThirdParty();
        Assert.True(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "dev1",
            ApprovalDecisions.Approved, "admin-a", T0, "manual approval")).Recorded);
        Assert.True(store.CheckCurrent(entry, "dev1").Approved);
        // The fleet pull: a fleet-scope reject recorded AFTER.
        Assert.True(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "*",
            ApprovalDecisions.Rejected, "admin-b", T0.AddHours(1), "fleet revocation")).Recorded);
        Assert.False(store.CheckCurrent(entry, "dev1").Approved);
        // A device approval explicitly re-recorded after the reject governs again.
        Assert.True(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "dev1",
            ApprovalDecisions.Approved, "admin-c", T0.AddHours(2), "re-approved after review"), supersede: true).Recorded);
        Assert.True(store.CheckCurrent(entry, "dev1").Approved);
    }

    // ---- rmm-2 F12: lifecycle scope/unknown + culture-stable halt hash -----

    [Fact]
    public void F12_Lifecycle_FutureAnchor_BucketsUnknown_AndScopeFilters()
    {
        var store = new InventoryStore();
        var future = Rmm26Shape.Record("dev-future", Scope) with { PurchaseDateUtc = T0.AddYears(2) };
        var other = Rmm26Shape.Record("dev-other", "co-2");
        store.ApplyBaseline(future, T0);
        store.ApplyBaseline(other, T0);
        var report = LifecycleReporting.Build(store, null, T0, scopeId: Scope);
        Assert.Equal(1, report.TotalDevices);
        Assert.Equal(1, report.AgeCohorts["unknown"]);
        Assert.Equal(0, report.AgeCohorts["0-3y"]);
    }

    [Fact]
    public void F12_RingHaltHash_CultureInvariant()
    {
        var evidence = new RingHaltEvidence("ring-1", 3, 1, 4, 0.75, "halted", T0);
        var before = Thread.CurrentThread.CurrentCulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = new CultureInfo("en-US");
            var us = evidence.EvidenceHash;
            Thread.CurrentThread.CurrentCulture = new CultureInfo("de-DE");
            var de = evidence.EvidenceHash;
            Assert.Equal(us, de);
        }
        finally { Thread.CurrentThread.CurrentCulture = before; }
    }

    // ---- rmm-3 F2: real check evaluator ------------------------------------

    [Fact]
    public void F2_LocalEvaluator_ObservesRealFacts_AndFailsByName()
    {
        var eval = new LocalRunbookCheckEvaluator();
        var fileStep = RunbookStep.Check("c1", "file", RunbookCheckKinds.FileExists,
            Path.GetTempFileName());
        Assert.True(eval.Evaluate(fileStep, "run", "dev1").Passed);
        var missingStep = RunbookStep.Check("c2", "file", RunbookCheckKinds.FileExists,
            Path.Combine(Path.GetTempPath(), "deskguest-no-such-" + Guid.NewGuid().ToString("N")));
        Assert.False(eval.Evaluate(missingStep, "run", "dev1").Passed);
        var diskStep = RunbookStep.Check("c3", "disk", RunbookCheckKinds.DiskFreePercent,
            Path.GetTempPath(), "0");
        Assert.True(eval.Evaluate(diskStep, "run", "dev1").Passed);
        var procStep = RunbookStep.Check("c4", "proc", RunbookCheckKinds.ProcessRunning,
            "deskguest-no-such-process-xyz");
        Assert.False(eval.Evaluate(procStep, "run", "dev1").Passed);
        var svcStep = RunbookStep.Check("c5", "svc", RunbookCheckKinds.ServiceRunning, "nosuchsvc");
        var svc = eval.Evaluate(svcStep, "run", "dev1");
        Assert.False(svc.Passed); // observed or named-unobservable — never assumed
    }

    // ---- rmm-3 F3/F8/F9: the bridge -----------------------------------------

    private static WorkItem SampleItem() => new(
        Id: "wi-1", Title: "t", DeviceId: "dev-1", ScopeId: Scope, State: WorkItemStates.Open,
        Owner: null, CreatedUtc: T0, UpdatedUtc: T0, ClosedUtc: null, Kind: WorkItemKinds.Manual,
        SourceAlertId: null, SourceConditionId: null, ExposureId: null, RequestId: null,
        RequesterName: null, HealthSummary: null, Attachments: Array.Empty<WorkItemAttachment>(),
        Closure: null, AuditSeqs: Array.Empty<long>());

    [Fact]
    public void F3_BridgeGuard_AdmitsLanPsa_RefusesMetadataAndLoopback()
    {
        Assert.Null(BridgeGuard.ValidateTarget("https://psa.corp.local/hook"));
        Assert.Null(BridgeGuard.ValidateTarget("https://192.168.1.20/hook"));
        Assert.NotNull(BridgeGuard.ValidateTarget("https://metadata.google.internal/hook"));
        Assert.NotNull(BridgeGuard.ValidateTarget("https://127.0.0.1/hook"));
        Assert.NotNull(BridgeGuard.ValidateTarget("https://169.254.169.254/hook"));
    }

    [Fact]
    public void F3_BridgePump_ResolverRebinding_RefusesSend()
    {
        var bridge = new WorkItemBridge(_ => new[] { IPAddress.Parse("10.0.0.9") });
        Assert.True(bridge.Configure("https://psa.example.org/hook", "0123456789abcdef-secret", "admin", T0).Ok);
        var (delivery, _) = bridge.Enqueue("opened", SampleItem(), T0);
        Assert.NotNull(delivery);
        var transport = new RecordingWebhookTransport();
        var changed = bridge.Pump(transport, T0);
        Assert.Empty(transport.Sent); // public name resolving private: never sent
        Assert.Equal(BridgeDeliveryStates.Failed, Assert.Single(changed).State);
    }

    [Fact]
    public void F8_SignedPayload_CarriesDeliveryId_AndFreshnessVerifies()
    {
        var payload = BridgeSigning.SignedPayload("opened", SampleItem(), "secret-secret-secret", T0, "dlv-123");
        Assert.Equal("dlv-123", BridgeSigning.PayloadDeliveryId(payload));
        Assert.True(BridgeSigning.VerifyPayload(payload, "secret-secret-secret", T0.AddMinutes(5)));
        Assert.False(BridgeSigning.VerifyPayload(payload, "secret-secret-secret", T0.AddHours(2))); // replayed later
    }

    [Fact]
    public void F9_DeadDeliveries_CanBeRedriven()
    {
        var bridge = new WorkItemBridge();
        Assert.True(bridge.Configure("https://psa.example.org/hook", "0123456789abcdef-secret", "admin", T0).Ok);
        bridge.Enqueue("opened", SampleItem(), T0);
        var failing = new RecordingWebhookTransport { Result = (false, "503") };
        var now = T0;
        for (var i = 0; i < WorkItemLimits.MaxBridgeAttempts; i++)
        {
            bridge.Pump(failing, now);
            now = now.AddDays(2); // outrun every backoff
        }
        Assert.Equal(BridgeDeliveryStates.Dead, Assert.Single(bridge.Deliveries).State);
        var moved = bridge.RedriveDead("ops-admin", now);
        Assert.Single(moved);
        Assert.Equal(BridgeDeliveryStates.Pending, Assert.Single(bridge.Deliveries).State);
        var ok = new RecordingWebhookTransport();
        bridge.Pump(ok, now);
        Assert.Equal(BridgeDeliveryStates.Delivered, Assert.Single(bridge.Deliveries).State);
    }

    // ---- rmm-3 F4: hub webhook pump ------------------------------------------

    private sealed class RecordingSink : IReportDeliverySink
    {
        public (bool Ok, string Detail) Deliver(ReportDestination destination, string fileName, string content) =>
            (true, "recorded");
    }

    private sealed class ThrowingTransport : IWebhookTransport
    {
        public (bool Ok, string Detail) Post(Uri target, string payloadJson) =>
            throw new InvalidOperationException("boom");
    }

    [Fact]
    public void F4_HubPump_ThrowingTransport_CountsFailedAttempt_NeverEscapes()
    {
        var signer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var hub = new HubWebhookHub(signer);
        Assert.True(hub.Configure(new WebhookEndpoint("ep1", "https://hooks.example.org/x",
            new HashSet<string> { HubEventKinds.AlertRaised }, true, "admin")).Ok);
        Assert.Single(hub.Raise(HubEventKinds.AlertRaised, "{}", T0));
        var changed = hub.Pump(new ThrowingTransport(), T0);
        var d = Assert.Single(changed);
        Assert.Equal(1, d.Attempts);
        Assert.Contains("transport threw", d.LastError ?? "");
    }

    // ---- rmm-3 F5/F6/F7: work-item store ---------------------------------------

    private static HealthAlertEvent Alert(string id, string deviceId = "dev-1") => new(
        id, deviceId, "disk-low", "disk", "warning", HealthAlertStates.Raised,
        T0, T0, 1, "disk below threshold", null, null, null, null, "endpoint");

    [Fact]
    public void F5_AlertItem_GetsDeviceScope_OrRefusedByName()
    {
        var scoped = new WorkItemStore(new ChainedAuditLog(), d => d == "dev-1" ? Scope : null);
        var (item, created, _) = scoped.OpenFromAlert(Alert("a1"), T0);
        Assert.True(created);
        Assert.Equal(Scope, item!.ScopeId);

        var unscoped = new WorkItemStore(new ChainedAuditLog(), _ => null);
        var (refused, created2, reason) = unscoped.OpenFromAlert(Alert("a2"), T0);
        Assert.False(created2);
        Assert.Null(refused);
        Assert.Contains("no enterprise scope", reason);
    }

    [Fact]
    public void F7_DeviceIdWithOutcomeToken_Refused_AndNoteCannotForgeOutcome()
    {
        var store = new WorkItemStore(new ChainedAuditLog());
        var (bad, _) = store.OpenManual("pc outcome=duplicate", Scope, "t", "opener", T0);
        Assert.Null(bad);
        var (item, _) = store.OpenManual("dev-1", Scope, "t", "opener", T0);
        Assert.NotNull(item);
        Assert.True(store.Close(item!.Id, WorkItemOutcomes.Resolved, "closer",
            "looks done outcome=duplicate honestly", T0).Ok);
        var (ok, _) = store.VerifyAgainstChain(item.Id);
        Assert.True(ok); // reconstruction reads the fixed-position token: resolved
    }

    [Fact]
    public void F6_Import_ValidatesItems_PersistsSpoofRefusals_AndAuditsRestore()
    {
        var audit = new ChainedAuditLog();
        var source = new WorkItemStore(audit);
        var (item, _) = source.OpenManual("dev-1", Scope, "real item", "opener", T0);
        Assert.NotNull(item);
        var exported = source.ExportJson();

        // Tamper-shape payload: same envelope, one valid + one forged item.
        var dto = new
        {
            Items = new[]
            {
                item!,
                item! with { Id = "wi-forged", Kind = "nonsense-kind" },
            },
            FloodRefusals = new Dictionary<string, int>(),
            SpoofRefusals = new Dictionary<string, int> { ["dev-9"] = 3 },
        };
        var wrapped = HubPersistence.Wrap("deskguest-work-items-v1",
            System.Text.Json.JsonSerializer.Serialize(dto));
        var target = new WorkItemStore(new ChainedAuditLog());
        Assert.Equal(1, target.ImportJson(wrapped));
        Assert.Equal(1, target.LastImportRefusedCount);
        Assert.Equal(3, target.SpoofRefusals["dev-9"]);
        Assert.Contains(target.Items, i => i.Id == item!.Id);
    }

    // ---- rmm-3 F10: dual control ------------------------------------------------

    [Fact]
    public void F10_ApproverCannotRedeemOwnGrant_AndPruneWorks()
    {
        var book = new FleetApprovalBook();
        var (ok, _, grant) = book.Grant("fleet_action", "alice", "bob", T0, TimeSpan.FromHours(1),
            argumentsJson: "{}");
        Assert.True(ok);
        var byApprover = book.Consume(grant!.GrantId, "fleet_action", T0, "{}", callerName: "alice");
        Assert.False(byApprover.Ok);
        Assert.Contains("approvers", byApprover.Reason);
        var byThird = book.Consume(grant.GrantId, "fleet_action", T0, "{}", callerName: "carol");
        Assert.True(byThird.Ok, byThird.Reason);
        Assert.Equal(1, book.Prune(T0)); // the consumed grant is pruned
    }

    // ---- rmm-3 F11: licence state names -------------------------------------------

    [Fact]
    public void F11_LicenceStates_NameTheShortfallHonestly()
    {
        Assert.Equal("deficit", LicenceStates.Deficit);
        Assert.Equal("surplus", LicenceStates.Surplus);
        Assert.Equal("deficit", LicenceFinding.KindDeficit);
        Assert.Equal("surplus", LicenceFinding.KindSurplus);
    }

    // ---- rmm-3 F12: durability ------------------------------------------------------

    [Fact]
    public void F12_LoopGuard_HistorySurvivesExportImport_AndEmptyRestoreFailsClosed()
    {
        var def = AutomationDefinition.Create("a1", "a1",
            new[] { RemediationStep.Create("s1", RemediationStepKinds.Wait, argument: "1") },
            cooldown: TimeSpan.FromMinutes(30), maxRunsPerWindow: 3);
        var guard = new RemediationLoopGuard();
        Assert.Null(guard.TryRecord(def, "dev-1", T0));
        var restored = new RemediationLoopGuard();
        Assert.True(restored.ImportJson(guard.ExportJson()));
        Assert.NotNull(restored.Check(def, "dev-1", T0.AddMinutes(5))); // cooldown survived the "restart"

        var empty = new RemediationLoopGuard();
        empty.SeedRestoredEmpty(T0);
        var anyDef = AutomationDefinition.Create("other", "other",
            new[] { RemediationStep.Create("s1", RemediationStepKinds.Wait, argument: "1") },
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 1000);
        Assert.NotNull(empty.Check(anyDef, "dev-2", T0.AddMinutes(1))); // global cap shut
    }

    [Fact]
    public void F12_ScheduledRunner_LastGeneratedSurvivesExportImport()
    {
        var runner = new ScheduledReportRunner();
        var def = new ScheduledReportDefinition("r1", ReportKinds.FleetHealth,
            ReportExportFormats.Json, 24, new ReportDestination(ReportDestinationKinds.LocalPath, "/tmp/x"),
            true, "admin", Scope);
        Assert.True(runner.Define(def).Ok);
        var sink = new RecordingSink();
        runner.RunDue((d, now) => ("rep-1", "{}", null), sink, T0);
        Assert.Equal(T0, runner.LastGenerated("r1"));
        var restored = new ScheduledReportRunner();
        Assert.True(restored.ImportStateJson(runner.ExportStateJson()));
        Assert.Equal(T0, restored.LastGenerated("r1"));
    }

    [Fact]
    public void F12_LicenceReportStore_SurvivesExportImport()
    {
        var report = LicencePositionBuilder.Build(
            new[] { Rmm26Shape.Ent("lic-1", "Microsoft Office", "ProPlus", 2) },
            new[] { Rmm26Shape.Record("dev-1", Scope, new[] { Rmm26Shape.Sw("Microsoft Office", "2021.5") }) },
            Rmm26Shape.ClassifierWithOffice(), null, Scope, T0);
        var store = new LicenceReportStore();
        Assert.True(store.Store(report).Ok);
        var restored = new LicenceReportStore();
        Assert.Equal(1, restored.ImportJson(store.ExportJson()));
        Assert.NotNull(restored.Get(report.Header.ReportId));
    }
}

// Minimal RMM-26-shaped fixtures (mirrors Rmm26Tests' helpers).
internal static class Rmm26Shape
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    public static HardwareSnapshot Hw() => new(
        "Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16, 16_000_000_000,
        "Windows 11 Pro", "26100.1", "10.0.26100", "1.0",
        Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0);

    public static DeviceInventoryRecord Record(string deviceId, string scope,
        IReadOnlyList<SoftwareItem>? software = null) => new(
        deviceId, scope, "WS-" + deviceId, Hw(), software ?? Array.Empty<SoftwareItem>(),
        new Dictionary<string, string>(), new HashSet<string>(),
        T0, T0, T0, 1);

    public static SoftwareItem Sw(string name, string version) => new(name, version, "Pub", null, "winget");

    public static LicenceEntitlement Ent(string id, string product, string? edition, int seats) => new(
        id, "co-1", product, edition, seats, null, "PO-2026-114 on file", "it-admin", T0, 1);

    public static EditionClassifier ClassifierWithOffice()
    {
        var c = new EditionClassifier();
        c.AddRule(new EditionRule("Microsoft Office", "ProPlus", "2021.0", "2024.0"));
        c.AddRule(new EditionRule("Microsoft Office", "Standard", "2019.0", "2021.0"));
        return c;
    }
}
