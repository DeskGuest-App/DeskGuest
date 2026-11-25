using System.Collections;
using System.Reflection;
using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Runbooks;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-20 D38 FIX lane — regression tests for packet 5f1749df
// (12 findings). Each test names its finding. Two predecessors
// left partial source fixes (F2 header hash in the engine, F5/F9
// in the library, F4/F6/F10/F11 fragments in the service — one of
// them non-compiling); this file pins every finding end-to-end.
public class Rmm20FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string Tech = "tech-1";
    private const string Lead = "lead-1";
    private const string SiteLead = "site-lead";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingRemediationStepExecutor Executor = new();
        public RecordingRunbookCheckEvaluator Checks = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public AutomationLibrary Automations = AutomationLibrary.Default();
        public RunbookService Service;

        public Rig(IEnumerable<string>? skippers = null)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new RunbookService(Audit, Policy,
                id => id == Dev ? Facts : null, Signer, Gate,
                Executor, Checks, () => Automations, null, () => Now,
                authorisedSkipperIds: skippers, authorisedApproverIds: new[] { Lead, SiteLead }, authorisedAttesterIds: new[] { Lead, SiteLead });
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev));

        public void AdmitRunbooks(params RunbookDefinition[] defs) =>
            Assert.True(Service.AdmitLocalLibrary(new RunbookLibrary("test-runbooks", 1, defs), "test").Allowed);

        public void AdmitAutomations(params AutomationDefinition[] defs) =>
            Automations = new AutomationLibrary("test-automation", 1, defs);
    }

    private static AutomationDefinition Auto(string id, params RemediationStep[] steps) =>
        AutomationDefinition.Create(id, id, steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    private static RemediationStep RStep(string id, string kind, string? target = null) =>
        RemediationStep.Create(id, kind, target: target);

    private static RunbookDefinition Book(string id, params RunbookStep[] steps) =>
        RunbookDefinition.Create(id, id, steps);

    // Reflection reach into the service's private run store — the
    // F2/F8 attacks rewrite the SERVICE's own record (the D38
    // packet's point: the old tests only forged caller-side copies).
    private static object RunStateOf(RunbookService svc, string runId)
    {
        var field = typeof(RunbookService).GetField("_runs", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var runs = (IDictionary)field.GetValue(svc)!;
        return runs[runId]!;
    }

    private static RunbookExecution LiveExec(RunbookService svc, string runId)
    {
        var state = RunStateOf(svc, runId);
        return (RunbookExecution)state.GetType().GetField("Exec")!.GetValue(state)!;
    }

    private static void ReplaceLiveExec(RunbookService svc, string runId, RunbookExecution forged)
    {
        var state = RunStateOf(svc, runId);
        state.GetType().GetField("Exec")!.SetValue(state, forged);
    }

    // ---- F1: failed-with-continue/route steps are journal-FAILED ----

    [Fact]
    public void F1_CheckFailsWithRoute_JournalJobFailed_StepFailedNeverCompleted()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("fix-it", RStep("f1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("routed",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "fix"),
            RunbookStep.Check("never", "skipped by route", RunbookCheckKinds.FileExists, @"C:\nope"),
            RunbookStep.Automated("fix", "fix it", "fix-it")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 3 percent");
        var (run, _) = rig.Service.StartRun("routed", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PartialFailure, run!.Status);
        var job = rig.Service.Journal.GetJob(run.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State);
        Assert.Equal(StepStates.Failed, job.Steps[0].State);
        Assert.Contains("c1", job.FailureReason!);
    }

    // ---- F2: run-level fields are tamper-evident ----------------------

    [Fact]
    public void F2_ServiceRecordRewritten_StatusAndInitiator_VerifyFails()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("cont",
            RunbookStep.Check("c1", "soft", RunbookCheckKinds.FileExists, @"C:\maybe",
                onFailure: RunbookFailurePolicies.Continue),
            RunbookStep.Check("c2", "hard", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("missing");
        var (run, _) = rig.Service.StartRun("cont", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PartialFailure, run!.Status);
        Assert.True(rig.Service.VerifyExecutionRecord(run.RunId).Ok);

        // Rewrite the SERVICE's record: outcome flipped to
        // succeeded, initiator swapped. Step records untouched, so
        // the step chain still recomputes — only the header anchor
        // can catch this, and now it does.
        var live = LiveExec(rig.Service, run.RunId);
        ReplaceLiveExec(rig.Service, run.RunId, live with
        {
            Status = RunbookRunStatuses.Succeeded,
            InitiatedBy = "mallory",
        });
        var (ok, why) = rig.Service.VerifyExecutionRecord(run.RunId);
        Assert.False(ok);
        Assert.Contains("rewritten after it was anchored", why);
    }

    [Fact]
    public void F2_StatusRunningForgery_OnFinishedRecord_VerifyFails()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("quick",
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("quick", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.Succeeded, run!.Status);
        Assert.True(rig.Service.VerifyExecutionRecord(run.RunId).Ok);

        // The packet's exact attack: set Status back to 'running'
        // to switch the anchor comparison off.
        var live = LiveExec(rig.Service, run.RunId);
        ReplaceLiveExec(rig.Service, run.RunId, live with { Status = RunbookRunStatuses.Running });
        var (ok, why) = rig.Service.VerifyExecutionRecord(run.RunId);
        Assert.False(ok);
        Assert.Contains("claims status 'running'", why);
    }

    // ---- F3: skipping a gate keeps the outcome honest ------------------

    [Fact]
    public void F3_SkipApprovalGatedAutomatedStep_OutcomePartialFailure_NeverSucceeded()
    {
        var rig = new Rig(skippers: new[] { Lead });
        rig.AdmitAutomations(Auto("wipe-temp", RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("gated-book",
            RunbookStep.Automated("a1", "clear", "wipe-temp", requiresApproval: true),
            RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("gated-book", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingApproval, run!.Status);
        var (ok, why) = rig.Service.SkipStep(run.RunId, "a1", Lead, "lead waived the restart this window", T0.AddMinutes(1));
        Assert.True(ok, why);
        Assert.Empty(rig.Executor.Calls); // the gated action never ran
        Assert.Equal(RunbookRunStatuses.PartialFailure, rig.Service.GetRun(run.RunId)!.Status);
    }

    [Fact]
    public void F3_SkipUnnamedHumanStep_OutcomePartialFailure()
    {
        var rig = new Rig(skippers: new[] { Lead });
        rig.AdmitRunbooks(Book("humans",
            RunbookStep.Human("h1", "sign", "Attest the fact."),
            RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("humans", Dev, Tech, null, T0);
        Assert.True(rig.Service.SkipStep(run!.RunId, "h1", Lead, "verified out of band, ticket 9", T0.AddMinutes(1)).Ok);
        Assert.Equal(RunbookRunStatuses.PartialFailure, rig.Service.GetRun(run.RunId)!.Status);
    }

    // ---- F4: skip authority is a registry, not "any second string" -----

    [Fact]
    public void F4_SkipHaltedCheck_ByUnregisteredActor_Refused_ByRegisteredActor_Works()
    {
        var rig = new Rig(skippers: new[] { Lead });
        rig.AdmitRunbooks(Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
            RunbookStep.Check("c2", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, run!.Status);

        var stranger = rig.Service.SkipStep(run.RunId, "c1", "random-tech-2", "I say skip", T0.AddMinutes(1));
        Assert.False(stranger.Ok);
        Assert.Contains("authorised-skipper registry", stranger.Reason);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, rig.Service.GetRun(run.RunId)!.Status);

        Assert.True(rig.Service.SkipStep(run.RunId, "c1", Lead, "risk accepted, ticket 4411", T0.AddMinutes(2)).Ok);
        Assert.Equal(RunbookRunStatuses.PartialFailure, rig.Service.GetRun(run.RunId)!.Status);
    }

    [Fact]
    public void F4_EmptySkipperRegistry_NobodyMaySkipAnUnnamedStep_FailClosed()
    {
        var rig = new Rig(); // no registry supplied
        rig.AdmitRunbooks(Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        var attempt = rig.Service.SkipStep(run!.RunId, "c1", Lead, "risk accepted", T0.AddMinutes(1));
        Assert.False(attempt.Ok);
        Assert.Contains("authorised-skipper registry", attempt.Reason);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, rig.Service.GetRun(run.RunId)!.Status);
    }

    // ---- F5: routes go forward only -------------------------------------

    [Fact]
    public void F5_SelfRouteAndBackwardRoute_RefusedAtAdmission_ForwardRoute_Admitted()
    {
        var self = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("c1", "t", RunbookCheckKinds.FileExists, @"C:\x",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "c1")) });
        Assert.Contains("not a LATER step", self.Validate());

        var backward = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Automated("a1", "t", "clear-disk-temp"),
            RunbookStep.Check("c1", "t", RunbookCheckKinds.FileExists, @"C:\x",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "a1")) });
        Assert.Contains("not a LATER step", backward.Validate());

        var forward = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("c1", "t", RunbookCheckKinds.FileExists, @"C:\x",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "fix"),
            RunbookStep.Automated("fix", "t", "clear-disk-temp")) });
        Assert.Null(forward.Validate());
    }

    // ---- F6: library-id discipline + signed-in-force closes local -------

    [Fact]
    public void F6_IdSwitchRetiresOldId_ReplayOfRetiredId_RefusedAtAnyRevision()
    {
        var rig = new Rig();
        var bookA = Book("a-book", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\Windows"));
        var bookB = Book("b-book", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\Windows"));
        Assert.True(rig.Service.AdmitLocalLibrary(new RunbookLibrary("lib-a", 5, new[] { bookA }), "test").Allowed);
        Assert.True(rig.Service.AdmitLocalLibrary(new RunbookLibrary("lib-b", 1, new[] { bookB }), "test").Allowed);
        // Rollback attempt: replay lib-a — at the OLD revision and
        // at a HIGHER one. The id is retired; both refuse.
        var replayOld = rig.Service.AdmitLocalLibrary(new RunbookLibrary("lib-a", 1, new[] { bookA }), "attack");
        Assert.False(replayOld.Allowed);
        Assert.Contains("retired", replayOld.Reason);
        Assert.False(rig.Service.AdmitLocalLibrary(new RunbookLibrary("lib-a", 99, new[] { bookA }), "attack").Allowed);
        Assert.Equal("lib-b", rig.Service.Library.Id);
    }

    [Fact]
    public void F6_OnceSignedLibraryInForce_LocalAdmissionClosed_AnonymousLocalRefused()
    {
        var rig = new Rig();
        var lib = new RunbookLibrary("signed-books", 1, new[] { Book("sb",
            RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\Windows")) });
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Service.ApplySignedLibrary(env).Allowed);
        var local = rig.Service.AdmitLocalLibrary(
            new RunbookLibrary("local-books", 1, new[] { Book("lb",
                RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\evil")) }), "test");
        Assert.False(local.Allowed);
        Assert.Contains("signed runbook library is in force", local.Reason);
        Assert.Equal("signed-books", rig.Service.Library.Id);

        var rig2 = new Rig();
        var anon = rig2.Service.AdmitLocalLibrary(new RunbookLibrary("x", 1, new[] { Book("b",
            RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\x")) }), " ");
        Assert.False(anon.Allowed);
        Assert.Contains("named admitting path", anon.Reason);
    }

    // ---- F7: a slow step does not block other runs or reads -------------

    [Fact]
    public void F7_SlowCheckOnOneRun_OtherRunsAndReadsStillProgress()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(
            Book("slow", RunbookStep.Check("c1", "slow check", RunbookCheckKinds.FileExists, @"C:\slow")),
            Book("human", RunbookStep.Human("h1", "sign", "Attest.")));
        var entered = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        rig.Checks.Hooks["c1"] = () =>
        {
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
        };
        RunbookExecution? slowRun = null;
        var thread = new Thread(() => { slowRun = rig.Service.StartRun("slow", Dev, Tech, null, T0).Run; });
        thread.Start();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)), "slow check never entered");

        // While run 1's check is blocked mid-evaluation, a second
        // run starts and parks, and reads answer — the service-wide
        // lock is NOT held across the evaluation.
        var (run2, _) = rig.Service.StartRun("human", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run2!.Status);
        Assert.NotNull(rig.Service.GetRun(run2.RunId));
        Assert.True(rig.Service.Attest(run2.RunId, "h1", Lead, T0.AddMinutes(1)).Ok);

        release.Set();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)));
        Assert.Equal(RunbookRunStatuses.Succeeded, slowRun!.Status);
        Assert.Equal(RunbookRunStatuses.Succeeded, rig.Service.GetRun(run2.RunId)!.Status);
    }

    // ---- F8: the pin guard and the anchor guard can actually fire -------

    [Fact]
    public void F8_PinnedDefinitionMutatedInService_ResumeFailsTheRun()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("proc",
            RunbookStep.Human("h1", "sign", "Attest."),
            RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);

        // Rewrite the service-held snapshot itself (the old guard
        // compared the snapshot against a hash derived from that
        // same snapshot, so it could never fire).
        var state = RunStateOf(rig.Service, run.RunId);
        var defField = state.GetType().GetField("Def")!;
        var def = (RunbookDefinition)defField.GetValue(state)!;
        defField.SetValue(state, def with
        {
            Steps = new[] { RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\evil") },
        });
        var (ok, why) = rig.Service.ResumeRun(run.RunId, T0.AddMinutes(5));
        Assert.False(ok);
        Assert.Contains("definition pin mismatch", why);
        Assert.Equal(RunbookRunStatuses.Failed, rig.Service.GetRun(run.RunId)!.Status);
    }

    // ---- F9: one-kind-per-step shape is complete -------------------------

    [Fact]
    public void F9_CrossKindFieldsAndUnboundedText_RefusedAtAdmission()
    {
        // automated step carrying check fields
        var bad1 = new RunbookLibrary("b", 1, new[] { Book("x",
            new RunbookStep("s", RunbookStepKinds.Automated, "t", "clear-disk-temp",
                RunbookCheckKinds.FileExists, @"C:\x", null, null, null, false, false, null, "halt", null, true)) });
        Assert.Contains("carries check/human fields", bad1.Validate());
        // human step carrying a check target
        var bad2 = new RunbookLibrary("b", 1, new[] { Book("x",
            new RunbookStep("s", RunbookStepKinds.HumanConfirmation, "t", null,
                null, @"C:\x", null, "Attest.", null, false, false, null, "halt", null, false)) });
        Assert.Contains("carries automated/check fields", bad2.Validate());
        // check step carrying attester fields
        var bad3 = new RunbookLibrary("b", 1, new[] { Book("x",
            new RunbookStep("s", RunbookStepKinds.Check, "t", null,
                RunbookCheckKinds.FileExists, @"C:\x", null, null, SiteLead, false, false, null, "halt", null, true)) });
        Assert.Contains("carries human attester fields", bad3.Validate());
        // check argument over bounds
        var bad4 = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("s", "t", RunbookCheckKinds.FileExists, @"C:\x", new string('a', 600))) });
        Assert.Contains("check argument over bounds", bad4.Validate());
        // route target without the route policy
        var bad5 = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("s", "t", RunbookCheckKinds.FileExists, @"C:\x",
                onFailure: RunbookFailurePolicies.Halt, routeStepId: "s2"),
            RunbookStep.Check("s2", "t", RunbookCheckKinds.FileExists, @"C:\y")) });
        Assert.Contains("route target exists only under the route policy", bad5.Validate());
    }

    // ---- F10: policy is checked BEFORE a decision is recorded -----------

    [Fact]
    public void F10_PolicyOff_AttestAndSkip_RefusedAndNotRecorded_RunAborts()
    {
        var rig = new Rig(skippers: new[] { Lead });
        rig.AdmitRunbooks(Book("proc",
            RunbookStep.Human("h1", "sign", "Attest."),
            RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);
        rig.SetPolicy(RunbookPolicyKeys.RunbooksEnabled, "false", "kill-1");

        // Decision attempted FIRST (the order the old tests never
        // exercised): it refuses, nothing is recorded, run aborts.
        var attest = rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(1));
        Assert.False(attest.Ok);
        Assert.Contains("decision was NOT recorded", attest.Reason);
        var after = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.AbortedPolicyDisabled, after.Status);
        Assert.Null(after.Steps[0].AttestedBy);
        Assert.NotEqual(RunbookStepStates.Done, after.Steps[0].State);

        // Skip on a fresh parked run, same discipline.
        var rig2 = new Rig(skippers: new[] { Lead });
        rig2.AdmitRunbooks(Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20")));
        rig2.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run2, _) = rig2.Service.StartRun("gated", Dev, Tech, null, T0);
        rig2.SetPolicy(RunbookPolicyKeys.RunbooksEnabled, "false", "kill-1");
        var skip = rig2.Service.SkipStep(run2!.RunId, "c1", Lead, "skip it", T0.AddMinutes(1));
        Assert.False(skip.Ok);
        var after2 = rig2.Service.GetRun(run2.RunId)!;
        Assert.NotEqual(RunbookStepStates.Skipped, after2.Steps[0].State);
        Assert.Null(after2.Steps[0].SkippedBy);
        Assert.Equal(RunbookRunStatuses.AbortedPolicyDisabled, after2.Status);
    }

    // ---- F11: skip reason is bounded + redacted ---------------------------

    [Fact]
    public void F11_SkipReason_OverBoundRefused_SecretInReasonRedactedInRecordAndAudit()
    {
        var rig = new Rig(skippers: new[] { Lead });
        rig.AdmitRunbooks(Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);

        var tooLong = rig.Service.SkipStep(run!.RunId, "c1", Lead, new string('x', 600), T0.AddMinutes(1));
        Assert.False(tooLong.Ok);
        Assert.Contains("bounded at", tooLong.Reason);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, rig.Service.GetRun(run.RunId)!.Status);

        var (ok, why) = rig.Service.SkipStep(run.RunId, "c1", Lead,
            "waived per ticket; password= hunter2 was on the ticket", T0.AddMinutes(2));
        Assert.True(ok, why);
        var rec = rig.Service.GetRun(run.RunId)!.Steps[0];
        Assert.DoesNotContain("hunter2", rec.SkipReason!);
        Assert.Contains("[redacted]", rec.SkipReason!);
        Assert.DoesNotContain("hunter2",
            string.Join(" ", rig.Audit.Entries.Select(e => e.Detail)));
    }

    // ---- F12: terminal runs are evicted at the bound ----------------------

    [Fact]
    public void F12_TerminalRunsEvictedBeyondBound_OldestFirst_ParkedRunsNeverEvicted()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(
            Book("quick", RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows")),
            Book("human", RunbookStep.Human("h1", "sign", "Attest.")));
        var (parked, _) = rig.Service.StartRun("human", Dev, Tech, null, T0);
        string? firstId = null;
        for (var i = 0; i < RunbookService.MaxRetainedTerminalRuns + 5; i++)
        {
            var (r, _) = rig.Service.StartRun("quick", Dev, Tech, null, T0.AddMinutes(i + 1));
            firstId ??= r!.RunId;
            Assert.Equal(RunbookRunStatuses.Succeeded, r!.Status);
        }
        Assert.Null(rig.Service.GetRun(firstId)); // oldest terminal run evicted
        Assert.NotNull(rig.Service.GetRun(parked!.RunId)); // parked run survives
        Assert.True(rig.Service.Runs.Count <= RunbookService.MaxRetainedTerminalRuns + 1);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "runbook_run_evicted");
    }

    // ---- CONV-F5: the automated-step mint must bind the alert's condition ----

    // Regression pin for the condition-id binding defect found by
    // CONV-F1: RunbookService.ExecuteAutomated built its synthetic
    // alert with ConditionId = exec.RunbookId but minted the
    // Automation envelope via RemediationBinding.Payload(...)
    // OMITTING the condition id. The real RMM-08 runner recomputes
    // the payload WITH alert.ConditionId and refuses on mismatch —
    // so every automated runbook step was refused and every run
    // with one ended `failed`. This test drives a genuine automated
    // runbook run end-to-end through the REAL runner binding (the
    // rig's RunbookService constructs the real RemediationRunner
    // over the real signed-command gate) and pins the POSITIVE
    // path by name: the step executes, the run succeeds, and no
    // binding-mismatch refusal appears anywhere in the audit.
    [Fact]
    public void ConvF5_AutomatedStep_MintsWithAlertConditionId_RunnerAccepts_RunSucceeds()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("cond-bound-book",
            RunbookStep.Automated("a1", "clear temp", "wipe-temp")));

        var (run, reason) = rig.Service.StartRun("cond-bound-book", Dev, Tech, null, T0);
        Assert.NotNull(run);
        // The positive path, pinned: NOT refused, NOT failed.
        Assert.Equal(RunbookRunStatuses.Succeeded, run!.Status);
        Assert.Equal(RunbookStepStates.Done, run.Steps[0].State);
        Assert.Null(run.Steps[0].Error);
        Assert.NotNull(run.Steps[0].InnerExecutionId);
        // The RMM-08 primitive executor genuinely ran the step.
        Assert.Equal(new[] { "w1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        // The runner accepted the envelope: it started AND completed
        // a remediation, and never refused one — above all, never
        // with the payload-binding-mismatch reason.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_completed");
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "remediation_refused");
        Assert.DoesNotContain("payload binding mismatch",
            string.Join(" ", rig.Audit.Entries.Select(e => e.Detail)));
        Assert.True(rig.Audit.Verify().Ok);
    }
}
