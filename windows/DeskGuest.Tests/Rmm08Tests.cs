using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-08 — Auto-remediation engine: trigger → action, self-healing
// under policy. Library model, dispatch gating, tiers + approvals,
// loop guard, bounded step interpreter, journal checkpointing,
// condition feedback, and the RMM-01 sink contract end-to-end.
public class Rmm08Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ---- fixtures ------------------------------------------------------

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingRemediationStepExecutor Executor = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public RemediationService Service;

        public Rig(bool signer = true, bool gate = true)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new RemediationService(Audit, Policy,
                id => id == Dev ? Facts : null,
                signer ? Signer : null, gate ? Gate : null, Executor, null, () => Now);
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev));

        public void Admit(params AutomationDefinition[] defs) =>
            Assert.True(Service.AdmitLocalLibrary(new AutomationLibrary("test-lib", 1, defs), "test").Allowed);
    }

    private static HealthAlertEvent Alert(string id = "alert-1", string condition = "svc-cond") => new(
        id, Dev, condition, ConditionKinds.ServiceStopped, AlertSeverities.Warning,
        HealthAlertStates.Raised, T0, T0, 1, "service 'Niagara' state 'Stopped'",
        null, null, null, null, "endpoint");

    private static AutomationDefinition Def(string id, params RemediationStep[] steps) =>
        AutomationDefinition.Create(id, id, steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    private static RemediationStep Step(string id, string kind, string? target = null) =>
        RemediationStep.Create(id, kind, target: target);

    // ---- library model ---------------------------------------------------

    [Fact]
    public void DefaultLibrary_IsValid_Tiered_AndBasTemplateShipsDisabled()
    {
        var lib = AutomationLibrary.Default();
        Assert.Null(lib.Validate());
        Assert.Equal(RemediationTiers.RequiresApproval,
            lib.Get("remove-prohibited-app")!.ApprovalTier); // uninstalling is a human's call
        Assert.False(lib.Get("restart-bas-service")!.Enabled); // site fact never guessed
        var round = AutomationLibrary.FromCanonicalJson(lib.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(lib.ContentHash, round!.ContentHash);
    }

    [Fact]
    public void Library_CanonicalRoundTrip_PreservesStepsGuardsAndChaining()
    {
        var def = AutomationDefinition.Create("combo", "combo", new[]
        {
            RemediationStep.Create("s1", RemediationStepKinds.RunScript, scriptBody: "echo hi",
                nextOnSuccess: "s3"),
            RemediationStep.Create("s2", RemediationStepKinds.Wait, argument: "5"),
            RemediationStep.Create("s3", RemediationStepKinds.RestartService, target: "Niagara",
                when: StepGuards.IfOutputContains, guardArgument: "hi", maxExecutions: 3),
        }, tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.FromMinutes(7),
            maxRunsPerWindow: 4, window: TimeSpan.FromHours(2), description: "round trip");
        var lib = new AutomationLibrary("rt", 3, new[] { def });
        var round = AutomationLibrary.FromCanonicalJson(lib.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(lib.ContentHash, round!.ContentHash);
        var rd = round.Get("combo")!;
        Assert.Equal(TimeSpan.FromMinutes(7), rd.Cooldown);
        Assert.Equal("s3", rd.Steps[0].NextOnSuccess);
        Assert.Equal(StepGuards.IfOutputContains, rd.Steps[2].When);
        Assert.Equal(3, rd.Steps[2].MaxExecutions);
    }

    // ---- dispatch + execution ---------------------------------------------

    [Fact]
    public void Dispatch_AutoAction_ExecutesStepsInOrder_OutputCaptured_JobDone_AuditChained()
    {
        var rig = new Rig();
        rig.Admit(Def("restart-niagara",
            Step("s1", RemediationStepKinds.RestartService, "Niagara"),
            Step("s2", RemediationStepKinds.ClearPath, @"C:\Windows\Temp")));
        rig.Executor.Results["s1"] = StepRunResult.Success("service restarted");

        var result = rig.Service.Dispatch("restart-niagara", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        Assert.Equal(new[] { "s1", "s2" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());

        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Succeeded, exec.Outcome);
        Assert.Equal("service restarted", exec.Steps[0].Output);
        Assert.Null(exec.ConditionCleared); // a run is not a clearance
        Assert.NotNull(exec.JobId);
        var job = rig.Service.Journal.GetJob(exec.JobId!);
        Assert.NotNull(job);
        Assert.Equal(JobStates.Done, job!.State);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_completed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Dispatch_UnknownRemediation_Refused_NothingExecutes_Audited()
    {
        var rig = new Rig();
        var result = rig.Service.Dispatch("no-such-action", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Contains("unknown remediation", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_dispatch_refused");
    }

    [Fact]
    public void Dispatch_PolicyKillSwitch_RefusesAll_Audited()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")));
        rig.SetPolicy(RemediationPolicyKeys.RemediationEnabled, "false", "off-1");
        var result = rig.Service.Dispatch("a", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Contains("rmm.remediation.enabled", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "remediation_dispatch_refused" && e.Detail.Contains("kill switch"));
    }

    [Fact]
    public void Dispatch_PerActionPolicyDisable_RefusesOnlyThatAction()
    {
        var rig = new Rig();
        rig.Admit(
            Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")),
            Def("b", Step("s1", RemediationStepKinds.RestartService, "Spooler")));
        rig.SetPolicy(RemediationPolicyKeys.ActionEnabled("a"), "false", "off-a");
        Assert.False(rig.Service.Dispatch("a", Alert(), T0).Dispatched);
        Assert.True(rig.Service.Dispatch("b", Alert("alert-2"), T0).Dispatched);
    }

    [Fact]
    public void Dispatch_NoDeviceFacts_FailsClosed()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")));
        var ghost = Alert() with { DeviceId = "ghost" };
        var result = rig.Service.Dispatch("a", ghost, T0);
        Assert.False(result.Dispatched);
        Assert.Contains("no device facts", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void Dispatch_NoSigner_Refuses_Rmm03()
    {
        var rig = new Rig(signer: false);
        rig.Admit(Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")));
        var result = rig.Service.Dispatch("a", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Contains("signer", result.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- tiers + approvals ---------------------------------------------------

    [Fact]
    public void RequiresApproval_ParksAgainstAlert_TriggerAloneNeverRuns_ApproveExecutes()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));

        var result = rig.Service.Dispatch("wipe-app", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Contains("pending_approval", result.Outcome);
        Assert.Empty(rig.Executor.Calls); // the trigger alone ran NOTHING
        var pending = Assert.Single(rig.Service.PendingApprovals);
        Assert.Equal("alert-1", pending.AlertId);
        Assert.Equal("wipe-app", pending.RemediationId);

        var (ok, reason) = rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(5));
        Assert.True(ok, reason);
        Assert.Single(rig.Executor.Calls);
        Assert.Equal(RemediationApprovalStatuses.Executed, rig.Service.GetApproval(pending.ApprovalId)!.Status);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_approval_parked");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_approval_executed" && e.Actor == "tech-1");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Deny_NeverExecutes_AndApprovalIsTerminal()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero));
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        Assert.True(rig.Service.Deny(pending.ApprovalId, "tech-1", T0.AddMinutes(1)).Ok);
        Assert.Empty(rig.Executor.Calls);
        Assert.Equal(RemediationApprovalStatuses.Denied, rig.Service.GetApproval(pending.ApprovalId)!.Status);
        Assert.False(rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(2)).Ok);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void PolicyTierRaise_AutoActionParks_WhenPolicyRequiresApproval()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")));
        rig.SetPolicy(RemediationPolicyKeys.ActionTier("a"), "requires_approval", "tier-a");
        var result = rig.Service.Dispatch("a", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Single(rig.Service.PendingApprovals);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- step model: guards, chaining, loops ---------------------------------

    [Fact]
    public void Steps_GuardsAndChaining_SkipAndJumpByResult()
    {
        var rig = new Rig();
        rig.Admit(Def("combo",
            RemediationStep.Create("probe", RemediationStepKinds.RestartService, target: "Niagara",
                nextOnSuccess: "fix"),
            RemediationStep.Create("never", RemediationStepKinds.StopService, target: "x"),
            RemediationStep.Create("fix", RemediationStepKinds.RestartService, target: "Niagara",
                when: StepGuards.IfOutputContains, guardArgument: "broken"),
            RemediationStep.Create("onfail", RemediationStepKinds.ClearPath, target: @"C:\Temp",
                when: StepGuards.IfPreviousFailed)));
        rig.Executor.Results["probe"] = StepRunResult.Success("status: broken");
        var result = rig.Service.Dispatch("combo", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Succeeded, exec.Outcome);
        // probe ran, chained straight to fix (never skipped by jump,
        // recorded skipped), fix's guard passed on probe's output,
        // onfail's guard failed (fix succeeded) so it skipped.
        Assert.Equal(new[] { "probe", "fix" }, rig.Executor.Calls.Select(c => c.StepId).ToArray());
        Assert.Contains(exec.Steps, s => s.StepId == "never" && s.State == StepExecutionStates.Skipped);
        Assert.Contains(exec.Steps, s => s.StepId == "onfail" && s.State == StepExecutionStates.Skipped);
    }

    [Fact]
    public void Steps_RetryLoop_SucceedsOnThirdAttempt_OutcomeSucceeded()
    {
        var rig = new Rig();
        var attempts = 0;
        rig.Executor.Results["try"] = StepRunResult.Failure("not yet");
        rig.Executor.Hooks["try"] = () =>
        {
            attempts++;
            if (attempts >= 3) rig.Executor.Results["try"] = StepRunResult.Success("ready");
        };
        rig.Admit(Def("retry",
            RemediationStep.Create("try", RemediationStepKinds.RestartService, target: "Niagara",
                nextOnFailure: "try", maxExecutions: 3),
            Step("after", RemediationStepKinds.Wait, null) with { Argument = "1" }));
        var result = rig.Service.Dispatch("retry", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Succeeded, exec.Outcome);
        Assert.Equal(3, rig.Executor.Calls.Count(c => c.StepId == "try"));
        Assert.Equal(3, exec.Steps.Count(s => s.StepId == "try"));
    }

    [Fact]
    public void Steps_WaitAndRerunPatch_DelegateHonestly()
    {
        var rig = new Rig();
        rig.Admit(Def("patch-again",
            Step("w", RemediationStepKinds.Wait, null) with { Argument = "30" },
            Step("rp", RemediationStepKinds.RerunPatch, "KB5001")));
        var result = rig.Service.Dispatch("patch-again", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        Assert.Equal(new[] { "KB5001" }, rig.Executor.PatchCalls.ToArray());
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Succeeded, exec.Outcome);
        Assert.Contains(exec.Steps, s => s.StepId == "w" && s.Output.Contains("wait 30s"));
    }

    // ---- loop guard -------------------------------------------------------------

    [Fact]
    public void LoopGuard_CooldownBlocks_ThenExpires()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("a", "a",
            new[] { Step("s1", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.FromMinutes(30), maxRunsPerWindow: 10));
        Assert.True(rig.Service.Dispatch("a", Alert("a1"), T0).Dispatched);
        var blocked = rig.Service.Dispatch("a", Alert("a2"), T0.AddMinutes(5));
        Assert.False(blocked.Dispatched);
        Assert.Contains("cooldown", blocked.Outcome);
        rig.Now = T0.AddMinutes(31); // D38-F3: the service clock advances with the caller
        Assert.True(rig.Service.Dispatch("a", Alert("a3"), T0.AddMinutes(31)).Dispatched);
        Assert.Equal(2, rig.Executor.Calls.Count);
    }

    [Fact]
    public void LoopGuard_MaxRunsPerWindow_BlocksAndRecovers()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("a", "a",
            new[] { Step("s1", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 2, window: TimeSpan.FromHours(1)));
        Assert.True(rig.Service.Dispatch("a", Alert("a1"), T0).Dispatched);
        Assert.True(rig.Service.Dispatch("a", Alert("a2"), T0.AddMinutes(1)).Dispatched);
        var blocked = rig.Service.Dispatch("a", Alert("a3"), T0.AddMinutes(2));
        Assert.False(blocked.Dispatched);
        Assert.Contains("run limit", blocked.Outcome);
        rig.Now = T0.AddMinutes(61); // D38-F3: the service clock advances with the caller
        Assert.True(rig.Service.Dispatch("a", Alert("a4"), T0.AddMinutes(61)).Dispatched);
    }

    // ---- feedback ---------------------------------------------------------------

    [Fact]
    public void Feedback_ConditionClearedAndPersisted_RecordedHonestly()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s1", RemediationStepKinds.RestartService, "Niagara")));
        rig.Service.Dispatch("a", Alert("a1"), T0);
        rig.Service.Dispatch("a", Alert("a2"), T0.AddMinutes(1));
        Assert.All(rig.Service.Executions, e => Assert.Null(e.ConditionCleared));

        Assert.Equal(1, rig.Service.RecordConditionFeedback("a1", true, T0.AddMinutes(2)));
        Assert.Equal(1, rig.Service.RecordConditionFeedback("a2", false, T0.AddMinutes(2)));
        Assert.True(rig.Service.ExecutionsForAlert("a1")[0].ConditionCleared);
        Assert.False(rig.Service.ExecutionsForAlert("a2")[0].ConditionCleared);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_condition_cleared");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_condition_persisted");
    }

    [Fact]
    public void Feedback_ConditionCleared_SupersedesPendingApproval()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero));
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        rig.Service.RecordConditionFeedback("alert-1", true, T0.AddMinutes(3));
        Assert.Equal(RemediationApprovalStatuses.SupersededConditionCleared,
            rig.Service.GetApproval(pending.ApprovalId)!.Status);
        Assert.False(rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(4)).Ok);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- signed library delivery ---------------------------------------------------

    [Fact]
    public void SignedLibrary_ValidEnvelope_Admitted()
    {
        var rig = new Rig();
        var lib = new AutomationLibrary("site-lib", 5, new[]
        {
            Def("site-action", Step("s1", RemediationStepKinds.RestartService, "Niagara")),
        });
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        rig.Now = T0;
        var verdict = rig.Service.ApplySignedLibrary(env);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Equal("site-lib", rig.Service.Library.Id);
        Assert.True(rig.Service.Dispatch("site-action", Alert(), T0).Dispatched);
    }

    // ---- RMM-01 sink contract, end to end -------------------------------------------

    [Fact]
    public void MonitorIntegration_ConditionFires_RemediationRuns_AlertResetsOnlyWhenConditionClears()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("restart-niagara", "restart-niagara",
            new[] { Step("r", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));

        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var stopped = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), new[] { new ServiceSample("Niagara", "Stopped") },
            Array.Empty<ProcessSample>(), Array.Empty<AppSample>(), Array.Empty<EventLogSample>(),
            null, null, Array.Empty<GuestSample>(), Array.Empty<string>());
        var running = stopped with
        {
            Services = new[] { new ServiceSample("Niagara", "Running") },
        };
        var monitor = new EndpointMonitorService(Dev, rig.Facts, rig.Policy,
            new FakeHealthCollector(stopped, running), centre, audit,
            null, null, rig.Service, () => rig.Now);
        monitor.AdmitLocalLibrary(new ConditionLibrary("mon-lib", 1, new[]
        {
            MonitorCondition.Create("svc", "svc", ConditionKinds.ServiceStopped, target: "Niagara",
                actions: new AlertActions(true, false, "restart-niagara"),
                cooldown: TimeSpan.FromMinutes(5)),
        }), "test");

        var first = monitor.RunCycle();
        Assert.Single(first.NewAlerts);
        Assert.Single(rig.Executor.Calls); // the remediation ran
        // HONESTY: the remediation ran, the service is still stopped
        // in this sample — the alert is NOT reset or acked by the run.
        Assert.Single(centre.ActiveAlerts);
        Assert.Equal(HealthAlertStates.Raised, centre.ActiveAlerts[0].State);
        Assert.Null(Assert.Single(rig.Service.Executions).ConditionCleared);

        // The condition actually clears: the monitor's own lifecycle
        // resets the alert, and feedback records the clearance
        // against the execution.
        rig.Now = T0.AddMinutes(1);
        var second = monitor.RunCycle();
        Assert.Single(second.AutoResetAlerts);
        Assert.Empty(centre.ActiveAlerts);
        rig.Service.RecordConditionFeedback(first.NewAlerts[0].AlertId, true, rig.Now);
        Assert.True(Assert.Single(rig.Service.Executions).ConditionCleared);
    }
}
