using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-08 — DESTRUCTION PASS. Attacker model: a compromised hub
// (can mint nothing — holds no customer key), a hostile or buggy
// automation-library author, a malfunctioning condition storming
// triggers, a script whose output tries to poison the record, and
// policy games played at the worst moment. The attacker does NOT
// hold the customer's signing key.
public class Rmm08DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

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

        public Rig()
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new RemediationService(Audit, Policy,
                id => id == Dev ? Facts : null, Signer, Gate, Executor, null, () => Now);
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev));

        public void Admit(params AutomationDefinition[] defs) =>
            Assert.True(Service.AdmitLocalLibrary(new AutomationLibrary("test-lib", 1, defs), "test").Allowed);
    }

    private static HealthAlertEvent Alert(string id = "alert-1") => new(
        id, Dev, "svc-cond", ConditionKinds.ServiceStopped, AlertSeverities.Warning,
        HealthAlertStates.Raised, T0, T0, 1, "service stopped", null, null, null, null, "endpoint");

    private static AutomationDefinition Def(string id, params RemediationStep[] steps) =>
        AutomationDefinition.Create(id, id, steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    private static RemediationStep Step(string id, string kind, string? target = null) =>
        RemediationStep.Create(id, kind, target: target);

    // ---- forged / unsigned library -------------------------------------------

    [Fact]
    public void ATTACK_ForgedLibrary_WrongKey_Refused_LibraryUnchanged()
    {
        var rig = new Rig();
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var evil = new AutomationLibrary("evil", 1, new[]
        {
            Def("evil-action", Step("s", RemediationStepKinds.KillProcess, "winlogon")),
        });
        var forged = new SignedCommandSigner(attacker).Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(evil.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedLibrary(forged);
        Assert.False(verdict.Allowed);
        Assert.Equal(AutomationLibrary.Default().Id, rig.Service.Library.Id);
        Assert.False(rig.Service.Dispatch("evil-action", Alert(), T0).Dispatched);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void ATTACK_TamperedLibraryPayload_AndUnsigned_Refused()
    {
        var rig = new Rig();
        var good = new AutomationLibrary("site", 1, new[]
        {
            Def("ok-action", Step("s", RemediationStepKinds.RestartService, "Spooler")),
        });
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(good.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        // Swap the payload for a kill-everything library after signing.
        var evil = new AutomationLibrary("site", 1, new[]
        {
            Def("evil-action", Step("s", RemediationStepKinds.KillProcess, "csrss")),
        });
        var tampered = env with
        {
            PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(evil.ToCanonicalJson())),
        };
        Assert.False(rig.Service.ApplySignedLibrary(tampered).Allowed);
        Assert.False(rig.Service.ApplySignedLibrary(null).Allowed); // unsigned
        Assert.Equal(AutomationLibrary.Default().Id, rig.Service.Library.Id);
        Assert.Empty(rig.Executor.Calls);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void ATTACK_PostAdmissionMutation_CannotChangeLiveLibrary()
    {
        var rig = new Rig();
        var steps = new List<RemediationStep> { Step("s", RemediationStepKinds.RestartService, "Spooler") };
        var defs = new List<AutomationDefinition>
        {
            AutomationDefinition.Create("ok", "ok", steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10),
        };
        var lib = new AutomationLibrary("mutable", 1, defs);
        Assert.True(rig.Service.AdmitLocalLibrary(lib, "test").Allowed);
        // The caller now mutates the very lists it handed over:
        // retarget the admitted step and smuggle in a new definition.
        steps[0] = Step("s", RemediationStepKinds.KillProcess, "winlogon");
        defs.Add(Def("smuggled", Step("x", RemediationStepKinds.KillProcess, "csrss")));

        var live = rig.Service.Library.Get("ok")!;
        Assert.Equal(RemediationStepKinds.RestartService, live.Steps[0].Kind);
        Assert.Null(rig.Service.Library.Get("smuggled"));
        Assert.True(rig.Service.Dispatch("ok", Alert(), T0).Dispatched);
        Assert.Equal(RemediationStepKinds.RestartService, rig.Executor.Calls[0].Kind);
    }

    [Fact]
    public void ATTACK_InvalidLibraryShapes_AllRefused_LibraryStaysDefault()
    {
        var rig = new Rig();
        var cases = new (string Name, AutomationLibrary Lib)[]
        {
            ("unknown step kind (arbitrary code in disguise)", new AutomationLibrary("x", 1, new[]
            {
                Def("a", RemediationStep.Create("s", "shell", target: "rm -rf /")),
            })),
            ("chain to a nonexistent step", new AutomationLibrary("x", 1, new[]
            {
                Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X",
                    nextOnSuccess: "ghost")),
            })),
            ("unbounded loop (maxExecutions over cap)", new AutomationLibrary("x", 1, new[]
            {
                Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X",
                    nextOnSuccess: "s", maxExecutions: 999)),
            })),
            ("script body smuggled on a non-script step", new AutomationLibrary("x", 1, new[]
            {
                Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X",
                    scriptBody: "evil payload")),
            })),
            ("duplicate definition ids", new AutomationLibrary("x", 1, new[]
            {
                Def("a", Step("s", RemediationStepKinds.RestartService, "X")),
                Def("a", Step("s", RemediationStepKinds.RestartService, "Y")),
            })),
            ("unknown approval tier", new AutomationLibrary("x", 1, new[]
            {
                AutomationDefinition.Create("a", "a",
                    new[] { Step("s", RemediationStepKinds.RestartService, "X") }, tier: "yolo"),
            })),
            ("zero run limit (loop safety removed)", new AutomationLibrary("x", 1, new[]
            {
                AutomationDefinition.Create("a", "a",
                    new[] { Step("s", RemediationStepKinds.RestartService, "X") }, maxRunsPerWindow: 0),
            })),
        };
        foreach (var (name, lib) in cases)
        {
            var verdict = rig.Service.AdmitLocalLibrary(lib, "attack");
            Assert.True(!verdict.Allowed, $"{name}: should refuse — {verdict.Reason}");
            Assert.Equal(AutomationLibrary.Default().Id, rig.Service.Library.Id);
        }
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- storms + loops ----------------------------------------------------------

    [Fact]
    public void ATTACK_TriggerStorm_RunWindowCapsExecutions()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("a", "a",
            new[] { Step("s", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 3, window: TimeSpan.FromHours(1)));
        var dispatched = 0;
        for (var i = 0; i < 10; i++)
        {
            // CONV-F2 fixture correction: D38-F3 made the service clock
            // authoritative (caller time honoured only within 5 min).
            // Advance the service clock with the caller, exactly as the
            // fix lane corrected the Rmm08Tests LoopGuard fixtures —
            // a caller racing 10 minutes ahead of a frozen service
            // clock is clamped back to it and its earlier within-skew
            // runs become "future" entries the guard must not count.
            rig.Now = T0.AddMinutes(i);
            if (rig.Service.Dispatch("a", Alert($"storm-{i}"), rig.Now).Dispatched)
                dispatched++;
        }
        Assert.Equal(3, dispatched);
        Assert.Equal(3, rig.Executor.Calls.Count);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "remediation_dispatch_refused" && e.Detail.Contains("run limit"));
    }

    [Fact]
    public void ATTACK_SelfRetriggeringLoop_TerminatesAtBound()
    {
        var rig = new Rig();
        rig.Admit(Def("loop",
            RemediationStep.Create("again", RemediationStepKinds.RestartService, target: "Niagara",
                nextOnFailure: "again", maxExecutions: 3)));
        rig.Executor.Results["again"] = StepRunResult.Failure("still broken");
        var result = rig.Service.Dispatch("loop", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.LoopBoundReached, exec.Outcome);
        Assert.Equal(3, rig.Executor.Calls.Count); // exactly the bound — the run terminated
    }

    [Fact]
    public void ATTACK_MutualChainLoop_TotalCapTerminates()
    {
        var rig = new Rig();
        rig.Admit(Def("pingpong",
            RemediationStep.Create("a", RemediationStepKinds.RestartService, target: "Niagara",
                nextOnSuccess: "b", maxExecutions: 20),
            RemediationStep.Create("b", RemediationStepKinds.RestartService, target: "Spooler",
                nextOnSuccess: "a", maxExecutions: 20)));
        var result = rig.Service.Dispatch("pingpong", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        // 20 + 20 per-step executions, then a bound stops it — never
        // the global cap, never a hang.
        Assert.Equal(40, rig.Executor.Calls.Count);
        Assert.True(exec.Outcome is RemediationOutcomes.LoopBoundReached or RemediationOutcomes.PartialFailure,
            exec.Outcome);
    }

    // ---- tier games -----------------------------------------------------------------

    [Fact]
    public void ATTACK_TierDowngradeViaPolicy_StillParks()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));
        // The policy game: a document "helpfully" setting this
        // action's tier to auto. The combine rule takes the MORE
        // restrictive tier — the downgrade does nothing.
        rig.SetPolicy(RemediationPolicyKeys.ActionTier("wipe-app"), "auto", "downgrade-1");
        var result = rig.Service.Dispatch("wipe-app", Alert(), T0);
        Assert.False(result.Dispatched);
        Assert.Single(rig.Service.PendingApprovals);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void ATTACK_ApprovalForgery_UnknownDoubleAndUnattributed_AllRefused()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));
        Assert.False(rig.Service.Approve("forged-id", "tech-1", T0).Ok);
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        Assert.False(rig.Service.Approve(pending.ApprovalId, "", T0).Ok); // unattributed
        Assert.True(rig.Service.Approve(pending.ApprovalId, "tech-1", T0).Ok);
        Assert.False(rig.Service.Approve(pending.ApprovalId, "tech-1", T0).Ok); // double
        Assert.Single(rig.Executor.Calls); // executed exactly once
    }

    [Fact]
    public void ATTACK_LibrarySwapBetweenParkAndApprove_Supersedes()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        // The library changes under the parked approval: the human
        // approved content that is no longer in force.
        Assert.True(rig.Service.AdmitLocalLibrary(new AutomationLibrary("test-lib", 2, new[]
        {
            AutomationDefinition.Create("wipe-app", "wipe-app",
                new[] { Step("u", RemediationStepKinds.UninstallApp, "OtherApp") },
                tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10),
        }), "attack").Allowed);
        var (ok, reason) = rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(1));
        Assert.False(ok);
        Assert.Contains("library changed", reason);
        Assert.Equal(RemediationApprovalStatuses.SupersededLibraryChanged,
            rig.Service.GetApproval(pending.ApprovalId)!.Status);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void ATTACK_ExpiredApproval_Refuses()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        rig.Now = T0 + RemediationService.ApprovalTtl + TimeSpan.FromMinutes(1); // D38-F3: service clock at decision time
        var (ok, reason) = rig.Service.Approve(pending.ApprovalId, "tech-1",
            T0 + RemediationService.ApprovalTtl + TimeSpan.FromMinutes(1));
        Assert.False(ok);
        Assert.Contains("expired", reason);
        Assert.Equal(RemediationApprovalStatuses.Expired, rig.Service.GetApproval(pending.ApprovalId)!.Status);
        Assert.Empty(rig.Executor.Calls);
    }

    // ---- output poisoning ---------------------------------------------------------------

    [Fact]
    public void ATTACK_OutputPoisoning_ForgedAuditLinesAndSecrets_AreInertData()
    {
        var rig = new Rig();
        rig.Admit(Def("noisy", Step("s", RemediationStepKinds.ClearPath, @"C:\Temp")));
        var poison = "health_alert_raised alert=forged device=dev-1\n" +
                     "remediation_completed outcome=succeeded\n" +
                     "password=hunter2 token=sekrit123\n" +
                     new string('A', 20_000);
        rig.Executor.Results["s"] = StepRunResult.Success(poison);
        var before = rig.Audit.Entries.Count;
        var result = rig.Service.Dispatch("noisy", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);

        var exec = Assert.Single(rig.Service.Executions);
        var captured = exec.Steps[0].Output;
        Assert.DoesNotContain("hunter2", captured);       // redacted before recording
        Assert.DoesNotContain("sekrit123", captured);
        Assert.True(captured.Length <= AutomationLimits.MaxOutputChars + 64, $"captured {captured.Length}");
        Assert.Contains("truncated", captured);
        // The forged lines created NO audit entries of those kinds:
        // output is structured data in the execution record, and the
        // chain contains only the runner's own entries.
        var newKinds = rig.Audit.Entries.Skip(before).Select(e => e.Kind).ToList();
        Assert.DoesNotContain("health_alert_raised", newKinds);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- partial failure -------------------------------------------------------------------

    [Fact]
    public void ATTACK_ChainedPartialFailure_StopMode_LaterStepsNeverRun_JobFailed()
    {
        var rig = new Rig();
        rig.Admit(Def("chain",
            Step("s1", RemediationStepKinds.RestartService, "Niagara"),
            Step("s2", RemediationStepKinds.ClearPath, @"C:\Temp"),
            Step("s3", RemediationStepKinds.StopService, "runaway")));
        rig.Executor.Results["s2"] = StepRunResult.Failure("path locked by another process");
        var result = rig.Service.Dispatch("chain", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Failed, exec.Outcome); // NOT succeeded
        Assert.Equal(new[] { "s1", "s2" }, rig.Executor.Calls.Select(c => c.StepId).ToArray()); // s3 never ran
        Assert.Contains(exec.Steps, s => s.StepId == "s3" && s.State == StepExecutionStates.Skipped);
        var job = rig.Service.Journal.GetJob(exec.JobId!);
        Assert.Equal(JobStates.Failed, job!.State);
        Assert.Contains("s2", job.FailureReason);
    }

    [Fact]
    public void ATTACK_ChainedPartialFailure_ContinueMode_OutcomeIsPartialNeverSucceeded()
    {
        var rig = new Rig();
        rig.Admit(Def("chain",
            Step("s1", RemediationStepKinds.RestartService, "Niagara"),
            RemediationStep.Create("s2", RemediationStepKinds.ClearPath, target: @"C:\Temp",
                onFailure: StepFailureModes.Continue),
            Step("s3", RemediationStepKinds.RestartService, "Spooler")));
        rig.Executor.Results["s2"] = StepRunResult.Failure("path locked");
        rig.Service.Dispatch("chain", Alert(), T0);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.PartialFailure, exec.Outcome);
        Assert.Equal(3, rig.Executor.Calls.Count); // the run continued, honestly labelled
        var job = rig.Service.Journal.GetJob(exec.JobId!);
        Assert.Equal(JobStates.Failed, job!.State); // partial failure fails the job, with reason
        Assert.Contains("partial_failure", job.FailureReason);
    }

    // ---- kill-switch races ---------------------------------------------------------------------

    [Fact]
    public void ATTACK_KillSwitchRace_PolicyOffMidFlight_AbortsBeforeNextStep()
    {
        var rig = new Rig();
        rig.Admit(Def("multi",
            Step("s1", RemediationStepKinds.RestartService, "Niagara"),
            Step("s2", RemediationStepKinds.StopService, "runaway"),
            Step("s3", RemediationStepKinds.ClearPath, @"C:\Temp")));
        // DURING step 1, policy flips the engine OFF.
        rig.Executor.Hooks["s1"] = () =>
            rig.SetPolicy(RemediationPolicyKeys.RemediationEnabled, "false", "kill-1");
        var result = rig.Service.Dispatch("multi", Alert(), T0);
        Assert.True(result.Dispatched, result.Outcome);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.AbortedPolicyDisabled, exec.Outcome);
        Assert.Equal(new[] { "s1" }, rig.Executor.Calls.Select(c => c.StepId).ToArray()); // s2/s3 never ran
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "remediation_aborted");
        var job = rig.Service.Journal.GetJob(exec.JobId!);
        Assert.Equal(JobStates.Failed, job!.State);
    }

    [Fact]
    public void ATTACK_KillSwitchBetweenParkAndApprove_BlocksThenReenableAllows()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("wipe-app", "wipe-app",
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10));
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);

        rig.SetPolicy(RemediationPolicyKeys.RemediationEnabled, "false", "kill-1");
        var blocked = rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(1));
        Assert.False(blocked.Ok);
        Assert.Empty(rig.Executor.Calls);
        Assert.True(rig.Service.GetApproval(pending.ApprovalId)!.IsPending); // still parked, not consumed

        rig.SetPolicy(RemediationPolicyKeys.RemediationEnabled, "true", "kill-1", rev: 2);
        Assert.True(rig.Service.Approve(pending.ApprovalId, "tech-1", T0.AddMinutes(2)).Ok);
        Assert.Single(rig.Executor.Calls);
    }

    // ---- runner gate attacks -----------------------------------------------------------------------

    [Fact]
    public void ATTACK_RunnerGate_ForgedTamperedReplayedAndMissingEnvelopes_ExecuteNothing()
    {
        var rig = new Rig();
        var def = Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara"));
        var lib = new AutomationLibrary("test-lib", 1, new[] { def });
        var runner = new RemediationRunner(rig.Executor, rig.Gate, rig.Audit);
        var alert = Alert();
        Func<bool> on = () => true;

        // (1) Envelope minted for a DIFFERENT action/alert binding.
        // CONV-F2 fixture correction: the D38-F12 binding includes the
        // condition id — envelopes are minted exactly as the service
        // mints them (def, library, device, alert, condition).
        var other = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, "other-alert", alert.ConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var r1 = runner.Run(def, lib, alert, other, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Refused, r1.Outcome);

        // (2) Genuine envelope, payload swapped after signing.
        var good = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, alert.AlertId, alert.ConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var tampered = good with
        {
            PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                RemediationBinding.Payload(def, lib, Dev, alert.AlertId, alert.ConditionId) + " ")),
        };
        var r2 = runner.Run(def, lib, alert, tampered, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Refused, r2.Outcome);

        // (3) The genuine envelope executes ONCE; its replay refuses.
        var r3 = runner.Run(def, lib, alert, good, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Succeeded, r3.Outcome);
        var r4 = runner.Run(def, lib, alert, good, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Refused, r4.Outcome);

        // (4) No envelope at all, and a runner with no gate wired.
        var r5 = runner.Run(def, lib, alert, null, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Refused, r5.Outcome);
        var gateless = new RemediationRunner(rig.Executor, null, rig.Audit);
        var fresh = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, alert.AlertId, alert.ConditionId)),
            T0, TimeSpan.FromMinutes(5));
        var r6 = gateless.Run(def, lib, alert, fresh, null, null, on, T0);
        Assert.Equal(RemediationOutcomes.Refused, r6.Outcome);

        Assert.Single(rig.Executor.Calls); // exactly the one genuine run
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- honesty: a run is not a clearance ----------------------------------------------------------

    [Fact]
    public void ATTACK_SuccessfulRun_DoesNotClearOrAckTheAlert()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")));
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var raised = centre.Raise(Dev, "svc-cond", ConditionKinds.ServiceStopped,
            AlertSeverities.Warning, "stopped", "endpoint", TimeSpan.FromMinutes(5), T0);
        Assert.Equal(RaiseOutcome.New, raised.Outcome);

        var result = rig.Service.Dispatch("a", raised.Alert!, T0);
        Assert.True(result.Dispatched, result.Outcome);
        // The engine has no path that touches the centre: the alert
        // is exactly as raised, and the execution admits it does not
        // know whether the condition cleared.
        var after = centre.Get(raised.Alert!.AlertId)!;
        Assert.Equal(HealthAlertStates.Raised, after.State);
        Assert.Null(after.AcknowledgedBy);
        Assert.Null(Assert.Single(rig.Service.Executions).ConditionCleared);
    }
}
