using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.Runbooks;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-20 DESTRUCTION — hostile pass over runbooks. Attacks:
// attestation forgery (executor attesting a step reserved for
// another attester; self-attestation where distinctness is
// required), self-approval of a gated step, wrong-approver
// approval, check-gate bypass (silent advance; unauthorised skip;
// skip without a reason), resume games (resume skipping the human
// step it paused on; resume of a terminal run), definition
// tampering post-signing (same-revision conflict; post-admission
// mutation of the caller's lists), execution-record rewriting
// (record vs step chain / audit anchor), runbook substitution
// mid-run (library revision under a paused run), kill-switch races
// (policy OFF mid-run and at resume), and journal tampering
// surfacing through record verification.
public class Rmm20DestructionTests
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

        public Rig()
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            // D38 F4 (fix lane): the fixture's authorised-skipper
            // registry — Lead and SiteLead hold skip authority in
            // these tests; an unregistered second string does not.
            Service = new RunbookService(Audit, Policy,
                id => id == Dev ? Facts : null, Signer, Gate,
                Executor, Checks, () => Automations, null, () => Now,
                authorisedSkipperIds: new[] { Lead, SiteLead }, authorisedApproverIds: new[] { Lead, SiteLead }, authorisedAttesterIds: new[] { Lead, SiteLead });
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev));

        public void AdmitRunbooks(long rev, params RunbookDefinition[] defs) =>
            Assert.True(Service.AdmitLocalLibrary(new RunbookLibrary("test-runbooks", rev, defs), "test").Allowed);

        public void AdmitAutomations(params AutomationDefinition[] defs) =>
            Automations = new AutomationLibrary("test-automation", 1, defs);
    }

    private static AutomationDefinition Auto(string id, params RemediationStep[] steps) =>
        AutomationDefinition.Create(id, id, steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    private static RemediationStep RStep(string id, string kind, string? target = null) =>
        RemediationStep.Create(id, kind, target: target);

    private static RunbookDefinition Book(string id, params RunbookStep[] steps) =>
        RunbookDefinition.Create(id, id, steps);

    // ---- attestation forgery -------------------------------------------------

    [Fact]
    public void Forgery_ExecutorAttestsStepReservedForAnotherAttester_Refused_RunStillPaused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("reserved",
            RunbookStep.Human("h1", "site sign-off", "Attest the site fact.", requiredAttesterId: SiteLead),
            RunbookStep.Check("c1", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("reserved", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);

        // The executing tech tries to attest the site lead's step —
        // by their own name, and by NAMING the site lead is not the
        // attack here (identity is the authenticated caller); the
        // forgery is the executor acting as attester at all.
        var forged = rig.Service.Attest(run.RunId, "h1", Tech, T0.AddMinutes(1));
        Assert.False(forged.Ok);
        Assert.Contains("reserved for attester", forged.Reason);
        var still = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, still.Status);
        Assert.Null(still.Steps[0].AttestedBy);
        Assert.Empty(rig.Checks.Calls); // nothing advanced

        // The reserved attester can attest.
        Assert.True(rig.Service.Attest(run.RunId, "h1", SiteLead, T0.AddMinutes(2)).Ok);
        Assert.Equal(RunbookRunStatuses.Succeeded, rig.Service.GetRun(run.RunId)!.Status);
    }

    [Fact]
    public void Forgery_SelfAttestationWhereDistinctAttesterRequired_Refused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("distinct",
            RunbookStep.Human("h1", "sign-off", "Attest.", requireDistinctAttester: true)));
        var (run, _) = rig.Service.StartRun("distinct", Dev, Tech, null, T0);
        var self = rig.Service.Attest(run.RunId, "h1", Tech, T0.AddMinutes(1));
        Assert.False(self.Ok);
        Assert.Contains("different from the executing tech", self.Reason);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, rig.Service.GetRun(run.RunId)!.Status);
        Assert.True(rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(2)).Ok);
    }

    [Fact]
    public void Forgery_AttestationOnWrongStepOrAfterCompletion_Refused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("two-humans",
            RunbookStep.Human("h1", "one", "Attest one."),
            RunbookStep.Human("h2", "two", "Attest two.")));
        var (run, _) = rig.Service.StartRun("two-humans", Dev, Tech, null, T0);
        // Attesting the FUTURE step while paused on h1.
        Assert.False(rig.Service.Attest(run.RunId, "h2", Lead, T0).Ok);
        Assert.True(rig.Service.Attest(run.RunId, "h1", Lead, T0).Ok);
        Assert.True(rig.Service.Attest(run.RunId, "h2", Lead, T0).Ok);
        Assert.Equal(RunbookRunStatuses.Succeeded, rig.Service.GetRun(run.RunId)!.Status);
        // Attesting a completed run.
        Assert.False(rig.Service.Attest(run.RunId, "h2", Lead, T0).Ok);
        // Blank attester.
        var (run2, _) = rig.Service.StartRun("two-humans", Dev, Tech, null, T0);
        Assert.False(rig.Service.Attest(run2!.RunId, "h1", "  ", T0).Ok);
    }

    // ---- self-approval -----------------------------------------------------------

    [Fact]
    public void SelfApproval_InitiatorApprovesOwnGatedStep_Refused_NothingRuns()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Automated("a1", "clear", "wipe-temp", requiresApproval: true)));
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        var self = rig.Service.ApproveStep(run!.RunId, "a1", Tech, T0.AddMinutes(1));
        Assert.False(self.Ok);
        Assert.Contains("self-approval refused", self.Reason);
        Assert.Empty(rig.Executor.Calls);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingApproval, rig.Service.GetRun(run.RunId)!.Status);
        Assert.True(rig.Service.ApproveStep(run.RunId, "a1", Lead, T0.AddMinutes(2)).Ok);
        Assert.Single(rig.Executor.Calls);
    }

    [Fact]
    public void WrongApprover_ApprovalByNonNamedApprover_Refused()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Automated("a1", "clear", "wipe-temp",
                requiresApproval: true, requiredApproverId: SiteLead)));
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.False(rig.Service.ApproveStep(run!.RunId, "a1", Lead, T0).Ok);
        Assert.Empty(rig.Executor.Calls);
        Assert.True(rig.Service.ApproveStep(run.RunId, "a1", SiteLead, T0).Ok);
        Assert.Single(rig.Executor.Calls);
    }

    // ---- check-gate bypass -----------------------------------------------------------

    [Fact]
    public void CheckBypass_FailedCheckCannotBeAttestedOrApprovedPast_OnlyRecordedSkipOrRecheck()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
            RunbookStep.Check("c2", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, run!.Status);
        // No attestation/approval path exists over a check gate.
        Assert.False(rig.Service.Attest(run.RunId, "c1", Lead, T0).Ok);
        Assert.False(rig.Service.ApproveStep(run.RunId, "c1", Lead, T0).Ok);
        Assert.Equal(new[] { "c1" }, rig.Checks.Calls.ToArray());
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, rig.Service.GetRun(run.RunId)!.Status);
    }

    [Fact]
    public void CheckBypass_SkipByExecutingTech_Refused_SkipWithoutReason_Refused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
            RunbookStep.Check("c2", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);

        var byTech = rig.Service.SkipStep(run!.RunId, "c1", Tech, "just skip it", T0.AddMinutes(1));
        Assert.False(byTech.Ok);
        Assert.Contains("other than the person executing", byTech.Reason);
        var noReason = rig.Service.SkipStep(run.RunId, "c1", Lead, " ", T0.AddMinutes(1));
        Assert.False(noReason.Ok);
        Assert.Contains("recorded reason", noReason.Reason);
        // Still halted; c2 never ran.
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, rig.Service.GetRun(run.RunId)!.Status);
        Assert.Equal(new[] { "c1" }, rig.Checks.Calls.ToArray());
    }

    [Fact]
    public void CheckBypass_RecordedSkipByAuthorisedActor_Advances_AndIsInTheRecordForever()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
            RunbookStep.Check("c2", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 2 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);

        var (ok, why) = rig.Service.SkipStep(run!.RunId, "c1", Lead,
            "site lead accepted the risk in ticket 4411; cleanup scheduled", T0.AddMinutes(5));
        Assert.True(ok, why);
        var done = rig.Service.GetRun(run.RunId)!;
        // The run completes the remaining steps, but a skipped FAILED
        // check keeps the outcome honest: partial, never succeeded.
        Assert.Equal(RunbookRunStatuses.PartialFailure, done.Status);
        var c1 = done.Steps[0];
        Assert.Equal(RunbookStepStates.Skipped, c1.State);
        Assert.Equal(false, c1.CheckPassed); // the failure is still in the record
        Assert.Equal(Lead, c1.SkippedBy);
        Assert.Contains("ticket 4411", c1.SkipReason!);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "runbook_step_skipped" && e.Actor == Lead);
        Assert.True(rig.Service.VerifyExecutionRecord(run.RunId).Ok);
    }

    [Fact]
    public void Skip_HumanStepReservedForAttester_SkipByThirdParty_Refused_SkipByAttester_Works()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("reserved",
            RunbookStep.Human("h1", "sign-off", "Attest.", requiredAttesterId: SiteLead)));
        var (run, _) = rig.Service.StartRun("reserved", Dev, Tech, null, T0);
        Assert.False(rig.Service.SkipStep(run!.RunId, "h1", Lead, "lead decides", T0).Ok);
        var (ok, why) = rig.Service.SkipStep(run.RunId, "h1", SiteLead, "fact verified out of band", T0);
        Assert.True(ok, why);
        // D38 F3 (fix lane): the attestation never happened — the
        // run completes but its outcome is partial_failure, never
        // succeeded. (This assertion previously locked in the
        // finding's behaviour and is amended with the fix.)
        Assert.Equal(RunbookRunStatuses.PartialFailure, rig.Service.GetRun(run.RunId)!.Status);
    }

    // ---- resume games -------------------------------------------------------------------

    [Fact]
    public void Resume_PausedAtHumanStep_ResumeDoesNotSkipIt_NothingAdvances()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(1, Book("proc",
            RunbookStep.Human("h1", "sign", "Attest."),
            RunbookStep.Automated("a1", "clear", "wipe-temp")));
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);

        var (ok, why) = rig.Service.ResumeRun(run.RunId, T0.AddMinutes(30));
        Assert.True(ok, why);
        Assert.Contains("still paused", why);
        var still = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, still.Status);
        Assert.Equal("h1", still.CurrentStepId);
        Assert.Empty(rig.Executor.Calls); // the automated step did NOT run
        Assert.Equal(1, still.ResumeCount);

        // And the run still completes normally via the human step.
        Assert.True(rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(31)).Ok);
        Assert.Equal(RunbookRunStatuses.Succeeded, rig.Service.GetRun(run.RunId)!.Status);
        Assert.Single(rig.Executor.Calls);
    }

    [Fact]
    public void Resume_TerminalRun_Refused_UnknownRun_Refused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("quick",
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var (run, _) = rig.Service.StartRun("quick", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.Succeeded, run!.Status);
        Assert.False(rig.Service.ResumeRun(run.RunId, T0.AddHours(1)).Ok);
        Assert.False(rig.Service.ResumeRun("no-such-run", T0).Ok);
    }

    // ---- definition tampering / substitution ------------------------------------------------

    [Fact]
    public void Tamper_SameRevisionDifferentContent_Refused_StaleRevision_Refused()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(2, Book("b",
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows")));
        var tampered = new RunbookLibrary("test-runbooks", 2, new[] { Book("b",
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\evil")) });
        var verdict = rig.Service.AdmitLocalLibrary(tampered, "attack");
        Assert.False(verdict.Allowed);
        Assert.Contains("conflicts", verdict.Reason);
        var stale = new RunbookLibrary("test-runbooks", 1, new[] { Book("b",
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\evil")) });
        Assert.False(rig.Service.AdmitLocalLibrary(stale, "attack").Allowed);
        Assert.Equal(@"C:\Windows", rig.Service.Library.Get("b")!.Steps[0].CheckTarget);
    }

    [Fact]
    public void Tamper_PostAdmissionMutationOfCallerLists_ChangesNothingLive()
    {
        var rig = new Rig();
        var steps = new List<RunbookStep>
        {
            RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows"),
        };
        var def = RunbookDefinition.Create("b", "b", steps);
        var books = new List<RunbookDefinition> { def };
        Assert.True(rig.Service.AdmitLocalLibrary(new RunbookLibrary("test-runbooks", 1, books), "test").Allowed);
        // The caller mutates the lists they still hold.
        steps.Add(RunbookStep.Human("hacked", "h", "Attest."));
        books.Add(Book("extra", RunbookStep.Check("c", "c", RunbookCheckKinds.FileExists, @"C:\x")));
        Assert.Single(rig.Service.Library.Get("b")!.Steps);
        Assert.Null(rig.Service.Library.Get("extra"));
    }

    [Fact]
    public void Substitution_LibraryRevisionMidRun_PausedRunExecutesPinnedDefinition()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(1, Book("proc",
            RunbookStep.Human("h1", "sign", "Attest."),
            RunbookStep.Automated("a1", "original automation", "wipe-temp")));
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        var pinnedHash = run!.DefinitionHash;

        // A new library revision swaps the runbook under the run:
        // step a1 now points at a DIFFERENT (nonexistent) automation
        // and the human step vanishes.
        rig.AdmitRunbooks(2, Book("proc",
            RunbookStep.Automated("a1", "substituted", "no-such-automation")));
        Assert.NotEqual(pinnedHash, RunbookLibrary.DefinitionHash(rig.Service.Library.Get("proc")!));

        // The paused run resumes on its PINNED definition.
        Assert.True(rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(1)).Ok);
        var done = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.Succeeded, done.Status);
        Assert.Equal(pinnedHash, done.DefinitionHash);
        Assert.Equal(new[] { "w1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        Assert.Equal(2, done.Steps.Count); // the original two steps, not the substituted one
    }

    // ---- execution-record rewriting --------------------------------------------------------------

    [Fact]
    public void RecordRewrite_ForgedCopyDoesNotTouchServiceRecord_VerifyStillOk()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Check("c1", "headroom", RunbookCheckKinds.DiskFreePercent, @"C:\", "20")));
        rig.Checks.Results["c1"] = CheckRunResult.Fail("free 1 percent");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, run!.Status);

        // An attacker holding the returned record rewrites the
        // failed check into a pass (records are values; the copy is
        // theirs to forge).
        var forged = run with
        {
            Status = RunbookRunStatuses.Succeeded,
            Steps = new[] { run.Steps[0] with { State = RunbookStepStates.Done, CheckPassed = true } },
        };
        Assert.False(forged.VerifyStepChain()); // the forgery breaks its own chain
        // The service's record is untouched and still verifies.
        var live = rig.Service.GetRun(run.RunId)!;
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, live.Status);
        Assert.Equal(false, live.Steps[0].CheckPassed);
        var (ok, why) = rig.Service.VerifyExecutionRecord(run.RunId);
        Assert.True(ok, why);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- kill-switch races ---------------------------------------------------------------------------

    [Fact]
    public void KillSwitch_PolicyOffMidRun_AbortsBeforeNextStep_DoneStepsStayDone()
    {
        var rig = new Rig();
        rig.AdmitAutomations(Auto("wipe-temp",
            RStep("w1", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.AdmitRunbooks(1, Book("proc",
            RunbookStep.Check("c1", "first", RunbookCheckKinds.FileExists, @"C:\Windows"),
            RunbookStep.Automated("a1", "clear", "wipe-temp")));
        // Policy flips OFF while c1 executes.
        rig.Checks.Hooks["c1"] = () =>
            rig.SetPolicy(RunbookPolicyKeys.RunbooksEnabled, "false", "kill-1");
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.AbortedPolicyDisabled, run!.Status);
        Assert.Equal(RunbookStepStates.Done, run.Steps[0].State);   // honestly done
        Assert.Equal(RunbookStepStates.Pending, run.Steps[1].State); // never ran
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void KillSwitch_PolicyOffAtResume_AbortsParkedRun()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("proc",
            RunbookStep.Human("h1", "sign", "Attest.")));
        var (run, _) = rig.Service.StartRun("proc", Dev, Tech, null, T0);
        rig.SetPolicy(RunbookPolicyKeys.RunbooksEnabled, "false", "kill-1");
        var (ok, why) = rig.Service.ResumeRun(run!.RunId, T0.AddMinutes(5));
        Assert.False(ok);
        Assert.Contains("disabled by policy at resume", why);
        Assert.Equal(RunbookRunStatuses.AbortedPolicyDisabled, rig.Service.GetRun(run.RunId)!.Status);
        // And attestation can no longer move it.
        Assert.False(rig.Service.Attest(run.RunId, "h1", Lead, T0.AddMinutes(6)).Ok);
    }

    // ---- hostile content ---------------------------------------------------------------------------

    [Fact]
    public void Hostile_CheckEvaluatorThrows_CheckRecordedFailed_RunHalts_NeverPasses()
    {
        var rig = new Rig();
        rig.AdmitRunbooks(1, Book("gated",
            RunbookStep.Check("c1", "boom", RunbookCheckKinds.ServiceRunning, "Niagara"),
            RunbookStep.Check("c2", "after", RunbookCheckKinds.FileExists, @"C:\Windows")));
        rig.Checks.Hooks["c1"] = () => throw new InvalidOperationException("probe exploded");
        var (run, _) = rig.Service.StartRun("gated", Dev, Tech, null, T0);
        Assert.Equal(RunbookRunStatuses.HaltedCheckFailed, run!.Status);
        Assert.Equal(false, run.Steps[0].CheckPassed);
        Assert.Contains("probe exploded", run.Steps[0].CheckObserved!);
        Assert.Equal(new[] { "c1" }, rig.Checks.Calls.ToArray());
    }

    [Fact]
    public void Hostile_ShippedCheckEvaluator_FailsByName_NeverAssumesPass()
    {
        var eval = new HostWiringRunbookCheckEvaluator();
        var step = RunbookStep.Check("c1", "c", RunbookCheckKinds.FileExists, @"C:\Windows");
        var result = eval.Evaluate(step, "run", Dev);
        Assert.False(result.Passed);
        Assert.Contains("host wiring pending", result.Observed);
    }
}
