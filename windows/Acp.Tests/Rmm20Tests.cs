using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Runbooks;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-20 — Runbooks: approval-gated SOP execution chains. Library
// model + builder data contract, composition over the RMM-08
// engine, checks gating progress, human attestations with attester
// rules, approval gates, recorded skips, resumability (RMM-15
// journal), definition pinning, policy control, execution records,
// starter runbooks, and the work-item link.
public class Rmm20Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string Tech = "tech-1";       // the executing tech / initiator
    private const string Lead = "lead-1";       // a second human
    private const string SiteLead = "site-lead"; // a named attester/approver

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

        public Rig(bool signer = true, bool gate = true)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new RunbookService(Audit, Policy,
                id => id == Dev ? Facts : null,
                signer ? Signer : null, gate ? Gate : null,
                Executor, Checks, () => Automations, null, () => Now,
                authorisedSkipperIds: new[] { Lead, SiteLead }, authorisedApproverIds: new[] { Lead, SiteLead }, authorisedAttesterIds: new[] { Lead, SiteLead });
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

    // ---- library model + builder contract --------------------------------

    [Fact]
    public void DefaultLibrary_IsValid_StartersShip_SiteFactsAreHumanPlaceholders()
    {
        var lib = RunbookLibrary.Default();
        Assert.Null(lib.Validate());
        Assert.NotNull(lib.Get("site-commissioning-checks"));
        Assert.NotNull(lib.Get("monthly-maintenance"));
        Assert.NotNull(lib.Get("new-user-setup"));
        // Honesty: every starter's site facts ride human-confirmation
        // steps whose prompts name them as site fact.
        foreach (var book in lib.Runbooks)
            Assert.Contains(book.Steps, s => s.Kind == RunbookStepKinds.HumanConfirmation);
        var commissioning = lib.Get("site-commissioning-checks")!;
        Assert.Contains(commissioning.Steps, s =>
            s.AttestationPrompt is not null && s.AttestationPrompt.Contains("SITE FACT"));
        // Automated steps reference only automation definitions that
        // ship in RMM-08's default library.
        var autos = AutomationLibrary.Default();
        foreach (var book in lib.Runbooks)
            foreach (var s in book.Steps.Where(s => s.Kind == RunbookStepKinds.Automated))
                Assert.NotNull(autos.Get(s.AutomationId!));
        var round = RunbookLibrary.FromCanonicalJson(lib.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(lib.ContentHash, round!.ContentHash);
    }

    [Fact]
    public void Library_CanonicalRoundTrip_PreservesStepsGatesAndAttesterRules()
    {
        var def = Book("combo",
            RunbookStep.Automated("a1", "do it", "clear-disk-temp", requiresApproval: true, requiredApproverId: Lead),
            RunbookStep.Check("c1", "check it", RunbookCheckKinds.DiskFreePercent, @"C:\", "25",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "h1"),
            RunbookStep.Human("h1", "attest it", "Attest the fact.", requiredAttesterId: SiteLead, requireDistinctAttester: true));
        var lib = new RunbookLibrary("rt", 3, new[] { def });
        Assert.Null(lib.Validate());
        var round = RunbookLibrary.FromCanonicalJson(lib.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(lib.ContentHash, round!.ContentHash);
        var rd = round.Get("combo")!;
        Assert.True(rd.Steps[0].RequiresApproval);
        Assert.Equal(Lead, rd.Steps[0].RequiredApproverId);
        Assert.Equal("h1", rd.Steps[1].RouteStepId);
        Assert.Equal(SiteLead, rd.Steps[2].RequiredAttesterId);
        Assert.Equal(RunbookLibrary.DefinitionHash(def),
            RunbookLibrary.DefinitionHash(round.Get("combo")!));
    }

    [Fact]
    public void Library_Validation_RefusesClosedVocabularyViolations_ByName()
    {
        // automated step with no automation id
        var bad1 = new RunbookLibrary("b", 1, new[] { Book("x",
            new RunbookStep("s", RunbookStepKinds.Automated, "t", null, null, null, null, null, null, false, false, null, "halt", null, true)) });
        Assert.Contains("names no automation definition", bad1.Validate());
        // unknown check kind
        var bad2 = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("s", "t", "vibes", "target")) });
        Assert.Contains("unknown check kind", bad2.Validate());
        // route to nowhere
        var bad3 = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Check("s", "t", RunbookCheckKinds.FileExists, @"C:\x",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "ghost")) });
        Assert.Contains("unknown step 'ghost'", bad3.Validate());
        // human step without a prompt
        var bad4 = new RunbookLibrary("b", 1, new[] { Book("x",
            RunbookStep.Human("s", "t", "")) });
        Assert.Contains("attestation prompt", bad4.Validate());
        // empty runbook
        var bad5 = new RunbookLibrary("b", 1, new[] { Book("x") });
        Assert.Contains("carries no steps", bad5.Validate());
    }

    [Fact]
    public void SignedLibrary_ValidEnvelope_Admitted_TamperedPayload_Refused()
    {
        var rig = new Rig();
        var lib = new RunbookLibrary("site-runbooks", 2, new[] { Book("site-book",
            RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\Windows")) });
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Service.ApplySignedLibrary(env).Allowed);
        Assert.Equal("site-runbooks", rig.Service.Library.Id);

        // Same envelope shape, payload altered after signing.
        var tamperedJson = lib.ToCanonicalJson().Replace("site-book", "evil-book!");
        var tampered = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5))
            with { PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(tamperedJson)) };
        Assert.False(rig.Service.ApplySignedLibrary(tampered).Allowed);
        Assert.Equal("site-runbooks", rig.Service.Library.Id);
        Assert.NotNull(rig.Service.Library.Get("site-book"));
    }

    // ---- happy path: composition over RMM-08 -------------------------------

    [Fact]
    public void Run_AutomatedAndCheckSteps_ExecuteThroughRmm08Engine_RecordComplete_JournalDone()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("maint",
            RunbookStep.Automated("a1", "clear temp", "wipe-temp"),
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20")));

        var (run, reason) = rig.Service.StartRun("maint", Dev, Tech, "wi-123", T0);
        Assert.NotNull(run);
        Assert.Equal(RunbookRunStatuses.Succeeded, run!.Status);
        // Composition proven: the RMM-08 primitive executor ran.
        Assert.Equal(new[] { "w1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        Assert.Equal(new[] { "c1" }, rig.Checks.Calls.ToArray());
        // Execution record: every step accounted for, inner id linked.
        Assert.Equal(RunbookStepStates.Done, run.Steps[0].State);
        Assert.NotNull(run.Steps[0].InnerExecutionId);
        Assert.Equal(true, run.Steps[1].CheckPassed);
        Assert.Equal("wi-123", run.WorkItemId);
        Assert.Single(rig.Service.RunsForWorkItem("wi-123"));
        // RMM-15: the run is a checkpointed job, done.
        Assert.NotNull(run.JobId);
        Assert.Equal(JobStates.Done, rig.Service.Journal.GetJob(run.JobId!)!.State);
        // Record verifies against its chain + audit anchor.
        Assert.True(rig.Service.VerifyExecutionRecord(run.RunId).Ok,
            rig.Service.VerifyExecutionRecord(run.RunId).Reason);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Run_CheckNotYetRun_RendersNotYetKnown_NeverPassed()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("paused-book",
            RunbookStep.Human("h1", "attest", "Attest something."),
            RunbookStep.Check("c1", "later check", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("paused-book", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);
        var check = run.Steps.Single(s => s.StepId == "c1");
        Assert.Null(check.CheckPassed);
        Assert.Equal("not yet known", check.CheckResultText);
    }

    // ---- human confirmations -------------------------------------------------

    [Fact]
    public void Run_PausesAtHumanStep_AttestationResumesAtThatStep_NothingReRuns()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("proc",
            RunbookStep.Automated("a1", "clear temp", "wipe-temp"),
            RunbookStep.Human("h1", "sign", "Attest the thing was done."),
            RunbookStep.Check("c1", "verify", RunbookCheckKinds.FileExists, @"C:\Windows")));

        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);
        Assert.Equal("h1", run.CurrentStepId);
        Assert.Single(rig.Executor.Calls);

        var (ok, why) = rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(3));
        Assert.True(ok, why);
        var done = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.Succeeded, done.Status);
        Assert.Single(rig.Executor.Calls); // a1 did NOT re-run on resume
        var h = done.Steps.Single(s => s.StepId == "h1");
        Assert.Equal(Lead, h.AttestedBy);
        Assert.Equal(T0.AddMinutes(3), h.AttestedUtc);
    }

    [Fact]
    public void Run_UnknownRunbook_NoFacts_PolicyOff_AllRefuseByName()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("b", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\x")));
        Assert.Null(rig.Service.StartRun("nope", Dev, Tech, null, T0).Run);
        var ghost = rig.Service.StartRun("b", "ghost-device", Tech, null, T0);
        Assert.Null(ghost.Run);
        Assert.Contains("no device facts", ghost.Reason);
        rig.SetPolicy(RunbookPolicyKeys.RunbooksEnabled, "false", "off-1");
        var off = rig.Service.StartRun("b", Dev, Tech, null, T0);
        Assert.Null(off.Run);
        Assert.Contains("disabled by policy", off.Reason);
        Assert.Empty(rig.Checks.Calls);
    }

    [Fact]
    public void Run_PerRunbookPolicyDisable_RefusesOnlyThatRunbook()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(
            Book("a", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\x")),
            Book("b", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\x")));
        rig.SetPolicy(RunbookPolicyKeys.RunbookEnabled("a"), "false", "off-a");
        Assert.Null(rig.Service.StartRun("a", Dev, Tech, null, T0).Run);
        Assert.NotNull(rig.Service.StartRun("b", Dev, Tech, null, T0).Run);
    }

    // ---- checks gating ---------------------------------------------------------

    [Fact]
    public void Check_FailsWithHalt_RunHaltsAndDoesNotAdvance_ReCheckAfterFix_Completes()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
            RunbookStep.Check("c2", "later", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 5 percent");

        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, run!.Status);
        Assert.Equal("c1", run.CurrentStepId);
        Assert.Equal(new[] { "c1" }, rig.Checks.Calls.ToArray()); // c2 NEVER ran
        Assert.Equal(false, run.Steps[0].CheckPassed);
        Assert.Equal("free 5 percent", run.Steps[0].CheckObserved);

        // The fact is fixed on the device; resume re-evaluates c1.
        rig.Checks.Results["c1"] = CheckRunResult.Pass("free 42 percent");
        var (ok, why) = rig.Service.ResumeRun(run.RunId, T0.AddMinutes(10));
        Assert.True(ok, why);
        var done = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.Succeeded, done.Status);
        Assert.Equal(2, done.Steps[0].Attempts);
        Assert.Equal(true, done.Steps[0].CheckPassed);
    }

    [Fact]
    public void Check_FailsWithContinue_RunAdvances_OutcomePartialFailure_NeverSucceeded()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("cont",
            RunbookStep.Check("c1", "soft check", RunbookCheckKinds.FileExists, @"C:\maybe",
                onFailure: RunbookFailurePolicies.Continue),
            RunbookStep.Check("c2", "hard check", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("missing");
        var (run, _) = rig.Service.StartRun("cont", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PartialFailure, run!.Status);
        Assert.Equal(RunbookStepStates.CheckFailed, run.Steps[0].State);
        Assert.Equal(RunbookStepStates.Done, run.Steps[1].State);
        // D38 F1 (fix lane): the journal job must agree — the failed
        // step is FAILED in the journal, never completed, and the
        // job is failed-with-reason, never Done.
        var job = rig.Service.Journal.GetJob(run.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State);
        Assert.Equal(StepStates.Failed, job.Steps[0].State);
    }

    [Fact]
    public void Check_FailsWithRoute_JumpsToHandlerStep_FailureRecorded()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("fix-it",
            RStep("f1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("routed",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20",
                onFailure: RunbookFailurePolicies.Route, routeStepId: "fix"),
            RunbookStep.Check("never", "skipped by route", RunbookCheckKinds.FileExists, @"C:\nope"),
            RunbookStep.Automated("fix", "fix it", "fix-it")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 3 percent");
        var (run, _) = rig.Service.StartRun("routed", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PartialFailure, run!.Status); // routed failure is not success
        Assert.Equal(new[] { "f1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        Assert.Equal(false, run.Steps[0].CheckPassed);
    }

    // ---- approval gates -----------------------------------------------------------

    [Fact]
    public void ApprovalGate_StepDoesNotRunUntilSecondHumanApproves()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(Book("gated-book",
            RunbookStep.Automated("a1", "clear temp", "wipe-temp", requiresApproval: true)));

        var (run, _) = rig.Service.StartRun("gated-book", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingApproval, run!.Status);
        Assert.Empty(rig.Executor.Calls); // the gate held: nothing ran

        var (ok, why) = rig.Service.ApproveStep(run.RunId, "a1", Lead, T0.AddMinutes(2));
        Assert.True(ok, why);
        Assert.Single(rig.Executor.Calls);
        var done = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.Succeeded, done.Status);
        Assert.Equal(Lead, done.Steps[0].ApprovedBy);
        Assert.Equal(T0.AddMinutes(2), done.Steps[0].ApprovedUtc);
    }

    // ---- automated failure -----------------------------------------------------------

    [Fact]
    public void AutomatedStep_InnerFailure_HaltsRunFailed_LaterStepsRecordedPendingNotDone()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("bad-auto",
            RStep("b1", RemediationStepKinds.RestartService, "Niagara")));
        rig.Executor.Results["b1"] = StepRunResult.Failure("service control refused");
        rig.AdmitRunbooks(Book("will-fail",
            RunbookStep.Automated("a1", "restart", "bad-auto"),
            RunbookStep.Check("c1", "later", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("will-fail", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.Failed, run!.Status);
        Assert.Equal(RunbookStepStates.Failed, run.Steps[0].State);
        Assert.Contains("bad-auto", run.Steps[0].Error!);
        Assert.Equal(RunbookStepStates.Pending, run.Steps[1].State);
        Assert.Empty(rig.Checks.Calls);
        Assert.Equal(JobStates.Failed, rig.Service.Journal.GetJob(run.JobId!)!.State);
    }

    [Fact]
    public void AutomatedStep_UnknownAutomation_FailsByName_NoFallbackExecutor()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(Book("dangling",
            RunbookStep.Automated("a1", "ghost", "no-such-automation")));
        var (run, _) = rig.Service.StartRun("dangling", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.Failed, run!.Status);
        Assert.Contains("unknown automation 'no-such-automation'", run.Steps[0].Error!);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- starter runbooks end-to-end ---------------------------------------------------

    [Fact]
    public void Starter_MonthlyMaintenance_RunsWithApprovalAndDistinctAttestation()
    {
        var rig = new Rig(); // default automation library + default runbook library
        var (run, reason) = rig.Service.StartRun("monthly-maintenance", Dev, Tech, null, T0);
        Assert.NotNull(run);
        // clear-temp ran, headroom check passed, spooler restart is gated.
        Assert.Equal(RunbookRunStatuses.PausedAwaitingApproval, run!.Status);
        Assert.Equal("restart-spooler", run.CurrentStepId);

        Assert.True(rig.Service.ApproveStep(run.RunId, "restart-spooler", Lead, T0.AddMinutes(1)).Ok);
        var paused = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, paused.Status);
        Assert.Equal("confirm-no-impact", paused.CurrentStepId);
        // Distinct-attester rule: the executing tech cannot sign off.
        Assert.False(rig.Service.Attest(run.RunId, "confirm-no-impact", Tech, T0.AddMinutes(2)).Ok);
        Assert.True(rig.Service.Attest(run.RunId, "confirm-no-impact", Lead, T0.AddMinutes(3)).Ok);
        Assert.Equal(RunbookRunStatuses.Succeeded, rig.Service.GetRun(run.RunId)!.Status);
    }
}
