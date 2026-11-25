using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Remediation;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-08 — D38 FIX lane (packet 30b35c10, 12 findings). One
// regression test per confirmed finding; the predecessor lane's
// partial fixes (loop-guard future-entry filter, TryRecord/Release,
// admission bounds, protected clear_path) are verified here too.
public class Rmm08FixTests
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

        public Rig(bool signer = true, bool gate = true)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new RemediationService(Audit, Policy,
                id => id == Dev ? Facts : null,
                signer ? Signer : null, gate ? Gate : null, Executor, null, () => Now);
        }

        public void Admit(params AutomationDefinition[] defs) =>
            Assert.True(Service.AdmitLocalLibrary(new AutomationLibrary("test-lib", 1, defs), "test").Allowed);

        public void AdmitLib(AutomationLibrary lib)
        {
            var v = Service.AdmitLocalLibrary(lib, "test");
            Assert.True(v.Allowed, v.Reason);
        }
    }

    private static HealthAlertEvent Alert(string id = "alert-1", string condition = "svc-cond") => new(
        id, Dev, condition, ConditionKinds.ServiceStopped, AlertSeverities.Warning,
        HealthAlertStates.Raised, T0, T0, 1, "service stopped", null, null, null, null, "endpoint");

    private static AutomationDefinition Def(string id, params RemediationStep[] steps) =>
        AutomationDefinition.Create(id, id, steps, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    private static RemediationStep Step(string id, string kind, string? target = null) =>
        RemediationStep.Create(id, kind, target: target);

    private static AutomationDefinition ApprovalDef(string id = "wipe-app") =>
        AutomationDefinition.Create(id, id,
            new[] { Step("u", RemediationStepKinds.UninstallApp, "BadApp") },
            tier: RemediationTiers.RequiresApproval, cooldown: TimeSpan.Zero, maxRunsPerWindow: 10);

    // ---- F1: envelope binds step CONTENT; runner checks def == library def ----

    [Fact]
    public void F1_SubstitutedSteps_GenuineEnvelope_Refused_NothingRuns()
    {
        var rig = new Rig();
        var good = Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara"));
        var lib = new AutomationLibrary("test-lib", 1, new[] { good });
        var runner = new RemediationRunner(rig.Executor, rig.Gate, rig.Audit);
        var alert = Alert();
        var envelope = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(good, lib, Dev, alert.AlertId, alert.ConditionId)),
            T0, TimeSpan.FromMinutes(5));

        // Same id, hostile steps, the GENUINE envelope for the good plan.
        var evil = Def("a", RemediationStep.Create("s", RemediationStepKinds.KillProcess, target: "winlogon"));
        var r = runner.Run(evil, lib, alert, envelope, null, null, () => true, T0);
        Assert.Equal(RemediationOutcomes.Refused, r.Outcome);
        Assert.Empty(rig.Executor.Calls);

        // And the genuine definition with its genuine envelope runs.
        var ok = runner.Run(good, lib, alert,
            rig.Signer.Sign(SignedCommandClasses.Automation,
                Encoding.UTF8.GetBytes(RemediationBinding.Payload(good, lib, Dev, alert.AlertId, alert.ConditionId)),
                T0, TimeSpan.FromMinutes(5)), null, null, () => true, T0);
        Assert.Equal(RemediationOutcomes.Succeeded, ok.Outcome);
        Assert.Single(rig.Executor.Calls);
    }

    [Fact]
    public void F1_PlanHash_BindsEveryStepField()
    {
        var a = Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X",
            argument: "1", onFailure: StepFailureModes.Stop));
        var variants = new[]
        {
            Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X", argument: "2", onFailure: StepFailureModes.Stop)),
            Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X", argument: "1", onFailure: StepFailureModes.Continue)),
            Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X", argument: "1", onFailure: StepFailureModes.Stop, maxExecutions: 2)),
            Def("a", RemediationStep.Create("s", RemediationStepKinds.RestartService, target: "X", argument: "1", onFailure: StepFailureModes.Stop, when: StepGuards.IfPreviousFailed)),
        };
        foreach (var v in variants)
            Assert.NotEqual(RemediationBinding.PlanHash(a), RemediationBinding.PlanHash(v));
    }

    // ---- F2: atomic single-use approvals + atomic loop guard ----

    [Fact]
    public void F2_ConcurrentApprove_ExecutesExactlyOnce()
    {
        var rig = new Rig();
        rig.Admit(ApprovalDef());
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        rig.Executor.Hooks["u"] = () => Thread.Sleep(250); // widen the old race window

        var results = new (bool Ok, string Reason)[2];
        Parallel.For(0, 2, i =>
            results[i] = rig.Service.Approve(pending.ApprovalId, $"tech-{i}", T0.AddMinutes(1)));
        Assert.Equal(1, results.Count(r => r.Ok));
        Assert.Single(rig.Executor.Calls); // exactly one execution
        Assert.Equal(RemediationApprovalStatuses.Executed,
            rig.Service.GetApproval(pending.ApprovalId)!.Status);
    }

    [Fact]
    public void F2_ConcurrentDispatch_NeverExceedsWindowCap()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("a", "a",
            new[] { Step("s", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.Zero, maxRunsPerWindow: 10, window: TimeSpan.FromHours(1)));
        var dispatched = 0;
        Parallel.For(0, 40, i =>
        {
            if (rig.Service.Dispatch("a", Alert($"c-{i}"), T0).Dispatched)
                Interlocked.Increment(ref dispatched);
        });
        Assert.Equal(10, dispatched);
        // The recording double's call list is not synchronised;
        // the dispatched count above is the atomicity evidence.
        Assert.True(rig.Executor.Calls.Count <= 10);
    }

    // ---- F3: the service clock governs every time gate ----

    [Fact]
    public void F3_FutureDatedDispatch_DoesNotPoisonLoopGuard()
    {
        var rig = new Rig();
        rig.Admit(AutomationDefinition.Create("a", "a",
            new[] { Step("s", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.FromMinutes(30), maxRunsPerWindow: 10));
        // A dispatch stamped a year in the future (bad monitor
        // clock) executes at the SERVICE clock, not the stamp.
        Assert.True(rig.Service.Dispatch("a", Alert("future"), T0.AddDays(365)).Dispatched);
        // Real-time dispatch 31 minutes later is NOT blocked by a
        // future timestamp sitting in the guard.
        rig.Now = T0.AddMinutes(31);
        Assert.True(rig.Service.Dispatch("a", Alert("real"), T0.AddMinutes(31)).Dispatched);
        Assert.Equal(2, rig.Executor.Calls.Count);
    }

    [Fact]
    public void F3_BackdatedApprove_CannotBypassTtl()
    {
        var rig = new Rig();
        rig.Admit(ApprovalDef());
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        // The approval is a day old on the service clock; approving
        // "at" its request time (the old bypass) must not execute.
        rig.Now = T0.AddHours(25);
        var (ok, reason) = rig.Service.Approve(pending.ApprovalId, "tech-1", pending.RequestedUtc);
        Assert.False(ok);
        Assert.Contains("expired", reason);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void F3_LoopGuard_FutureEntriesDoNotCount()
    {
        var def = AutomationDefinition.Create("a", "a",
            new[] { Step("s", RemediationStepKinds.RestartService, "Niagara") },
            cooldown: TimeSpan.FromMinutes(30), maxRunsPerWindow: 1);
        var guard = new RemediationLoopGuard();
        Assert.Null(guard.TryRecord(def, Dev, T0.AddDays(30))); // future-dated record
        // At real time the future entry neither cools down nor
        // consumes the window (predecessor fix, verified here).
        Assert.Null(guard.Check(def, Dev, T0));
    }

    // ---- F4: the Error channel is redacted + capped like Output ----

    [Fact]
    public void F4_PoisonedError_RedactedAndCapped_InRecordAuditAndJournal()
    {
        var rig = new Rig();
        rig.Admit(Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")));
        var poison = "password=hunter2\nremediation_completed outcome=succeeded " + new string('B', 20_000);
        rig.Executor.Results["s"] = StepRunResult.Failure(poison);
        Assert.True(rig.Service.Dispatch("a", Alert(), T0).Dispatched);

        var exec = Assert.Single(rig.Service.Executions);
        var err = Assert.Single(exec.Steps).Error!;
        Assert.DoesNotContain("hunter2", err);
        Assert.True(err.Length <= AutomationLimits.MaxOutputChars + 64, $"error {err.Length}");
        Assert.All(rig.Audit.Entries, e => Assert.DoesNotContain("hunter2", e.Detail));
        var job = rig.Service.Journal.GetJob(exec.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State);
        Assert.DoesNotContain("hunter2", job.FailureReason ?? "");
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- F5: journal state matches the run's outcome ----

    [Fact]
    public void F5_ForwardChainBypass_SucceededRun_JobDone()
    {
        var rig = new Rig();
        rig.Admit(Def("chain",
            RemediationStep.Create("a", RemediationStepKinds.RestartService, target: "Niagara", nextOnSuccess: "c"),
            Step("b", RemediationStepKinds.RestartService, "Spooler"),
            Step("c", RemediationStepKinds.ClearPath, @"C:\Temp")));
        Assert.True(rig.Service.Dispatch("chain", Alert(), T0).Dispatched);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Succeeded, exec.Outcome);
        Assert.Equal(new[] { "a", "c" }, rig.Executor.Calls.Select(x => x.StepId).ToArray());
        var job = rig.Service.Journal.GetJob(exec.JobId!)!;
        Assert.Equal(JobStates.Done, job.State); // not left running with b/c pending
    }

    [Fact]
    public void F5_ReentryThenStopFailure_JobFailed_NotDone()
    {
        var rig = new Rig();
        var aCalls = 0;
        rig.Executor.Hooks["a"] = () =>
        {
            aCalls++;
            if (aCalls >= 2) rig.Executor.Results["a"] = StepRunResult.Failure("a broke on re-entry");
        };
        rig.Admit(Def("loop",
            // CONV-F2 fixture correction: re-entry is bounded by the
            // RE-ENTERED step's own MaxExecutions (default 1 — the
            // gated loop-bound rule the SelfRetriggering/MutualChain
            // attacks pin). Step a must carry the loop's bound or the
            // bound correctly stops the run before a can re-execute
            // and fail; b's bound alone never authorised a's re-entry.
            RemediationStep.Create("a", RemediationStepKinds.RestartService, target: "Niagara",
                maxExecutions: 3),
            RemediationStep.Create("b", RemediationStepKinds.RestartService, target: "Spooler",
                nextOnSuccess: "a", maxExecutions: 3)));
        Assert.True(rig.Service.Dispatch("loop", Alert(), T0).Dispatched);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Equal(RemediationOutcomes.Failed, exec.Outcome);
        var job = rig.Service.Journal.GetJob(exec.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State); // a terminal Done would lie about this run
    }

    // ---- F6: refusals don't burn the guard; parking is bounded + deduped ----

    [Fact]
    public void F6_RunnerRefusals_DoNotConsumeLoopGuard()
    {
        var rig = new Rig(gate: false); // the runner refuses every execution
        rig.Admit(Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")));
        for (var i = 0; i < 5; i++)
            Assert.False(rig.Service.Dispatch("a", Alert($"r-{i}"), T0).Dispatched);
        var def = rig.Service.Library.Get("a")!;
        Assert.Equal(0, rig.Service.LoopGuard.RunsInWindow(def, Dev, T0));
    }

    [Fact]
    public void F6_Parking_DedupedPerAlert_AndCapped()
    {
        var rig = new Rig();
        rig.Admit(ApprovalDef());
        rig.Service.Dispatch("wipe-app", Alert("same"), T0);
        rig.Service.Dispatch("wipe-app", Alert("same"), T0);
        Assert.Single(rig.Service.PendingApprovals); // one request per alert, not per trigger

        for (var i = 0; i < RemediationService.MaxPendingApprovals; i++)
            rig.Service.Dispatch("wipe-app", Alert($"storm-{i}"), T0);
        Assert.Equal(RemediationService.MaxPendingApprovals, rig.Service.PendingApprovals.Count);
        var over = rig.Service.Dispatch("wipe-app", Alert("one-too-many"), T0);
        Assert.False(over.Dispatched);
        Assert.Contains("cap", over.Outcome);
    }

    // ---- F7: feedback honesty + parked alert state carried ----

    [Fact]
    public void F7_Feedback_RefusedExecutionsNeverReadCleared()
    {
        var rig = new Rig(gate: false);
        rig.Admit(Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")));
        rig.Service.Dispatch("a", Alert("r1"), T0); // runner refuses → Refused execution
        Assert.Equal(0, rig.Service.RecordConditionFeedback("r1", true, T0.AddMinutes(1)));
        Assert.Null(Assert.Single(rig.Service.Executions).ConditionCleared);
    }

    [Fact]
    public void F7_ParkedApproval_CarriesTheAlertsParkedState()
    {
        var rig = new Rig();
        rig.Admit(ApprovalDef());
        rig.Service.Dispatch("wipe-app", Alert(), T0);
        var pending = Assert.Single(rig.Service.PendingApprovals);
        Assert.Equal(HealthAlertStates.Raised, pending.AlertState); // captured, not fabricated at approve time
    }

    // ---- F8: revision discipline survives id switches + casing ----

    [Fact]
    public void F8_CrossIdRollback_Refused_AndCasingCannotSkipRevision()
    {
        var rig = new Rig();
        rig.AdmitLib(new AutomationLibrary("site-lib", 5, new[]
        {
            Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")),
        }));
        // Switch ids: site-lib is retired by the replacement.
        rig.AdmitLib(new AutomationLibrary("x", 1, new[]
        {
            Def("b", Step("s", RemediationStepKinds.RestartService, "Spooler")),
        }));
        var back = rig.Service.AdmitLocalLibrary(new AutomationLibrary("site-lib", 3, new[]
        {
            Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara")),
        }), "attack");
        Assert.False(back.Allowed);
        Assert.Contains("retired", back.Reason);
        Assert.Equal("x", rig.Service.Library.Id);

        // Casing: 'X' r0/r1 is the SAME library as live 'x' r1.
        var cased = rig.Service.AdmitLocalLibrary(new AutomationLibrary("X", 1, new[]
        {
            Def("evil", Step("s", RemediationStepKinds.RestartService, "Evil")),
        }), "attack");
        Assert.False(cased.Allowed); // same id+revision, different content = conflict
        Assert.Null(rig.Service.Library.Get("evil"));
    }

    // ---- F9: wait reaches the executor ----

    [Fact]
    public void F9_WaitStep_IsDelegatedToTheExecutor()
    {
        var rig = new Rig();
        rig.Admit(Def("pacer",
            Step("w", RemediationStepKinds.Wait, null) with { Argument = "30" },
            Step("s", RemediationStepKinds.RestartService, "Niagara")));
        Assert.True(rig.Service.Dispatch("pacer", Alert(), T0).Dispatched);
        Assert.Contains(rig.Executor.Calls, c => c.StepId == "w" && c.Kind == RemediationStepKinds.Wait);
        var exec = Assert.Single(rig.Service.Executions);
        Assert.Contains("wait 30s", Assert.Single(exec.Steps, s => s.StepId == "w").Output);
    }

    // ---- F10: throwing policy/journal never escape; record always lands ----

    [Fact]
    public void F10_ThrowingPolicyCallback_AbortsRun_RecordStored()
    {
        var rig = new Rig();
        var def = Def("a",
            Step("s1", RemediationStepKinds.RestartService, "Niagara"),
            Step("s2", RemediationStepKinds.RestartService, "Spooler"));
        var lib = new AutomationLibrary("test-lib", 1, new[] { def });
        var runner = new RemediationRunner(rig.Executor, rig.Gate, rig.Audit);
        var envelope = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, "alert-1", "svc-cond")),
            T0, TimeSpan.FromMinutes(5));
        var journal = new JobJournal(null, null);
        var journalEnvelope = rig.Signer.Sign(SignedCommandClasses.ScriptExec,
            Encoding.UTF8.GetBytes($"script_chain|{def.Id}|{RemediationBinding.PlanHash(def)}"),
            T0, TimeSpan.FromMinutes(5));
        var calls = 0;
        var exec = runner.Run(def, lib, Alert(), envelope, journal, journalEnvelope,
            () => { if (++calls > 1) throw new InvalidOperationException("policy engine blew up"); return true; }, T0);
        Assert.Equal(RemediationOutcomes.AbortedPolicyDisabled, exec.Outcome);
        Assert.Single(rig.Executor.Calls); // s2 never ran, and Run did not throw
        var job = journal.GetJob(exec.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State);
    }

    // ---- F11: admission bounds + high-impact tier floor ----

    [Fact]
    public void F11_HighImpactKinds_AtAutoTier_Refused_BoundedFieldsEnforced()
    {
        var rig = new Rig();
        foreach (var kind in new[] { RemediationStepKinds.RunScript, RemediationStepKinds.KillProcess, RemediationStepKinds.UninstallApp })
        {
            var step = kind == RemediationStepKinds.RunScript
                ? RemediationStep.Create("s", kind, scriptBody: "echo hi")
                : Step("s", kind, "target");
            var verdict = rig.Service.AdmitLocalLibrary(
                new AutomationLibrary("hi", 1, new[] { Def("a", step) }), "attack");
            Assert.False(verdict.Allowed, kind);
            Assert.Contains("high-impact", verdict.Reason);
        }
        // The same content at requires_approval IS admissible.
        Assert.True(rig.Service.AdmitLocalLibrary(new AutomationLibrary("hi", 1, new[]
        {
            AutomationDefinition.Create("a", "a",
                new[] { RemediationStep.Create("s", RemediationStepKinds.RunScript, scriptBody: "echo hi") },
                tier: RemediationTiers.RequiresApproval),
        }), "test").Allowed);
        // Unbounded free-text fields refuse (predecessor fix, verified).
        var fat = rig.Service.AdmitLocalLibrary(new AutomationLibrary("fat", 1, new[]
        {
            Def("a", Step("s", RemediationStepKinds.RestartService, "X") with
            { Argument = new string('x', AutomationLimits.MaxArgumentLength + 1) }),
        }), "attack");
        Assert.False(fat.Allowed);
        // Protected clear_path targets refuse (predecessor fix, verified).
        var root = rig.Service.AdmitLocalLibrary(new AutomationLibrary("root", 1, new[]
        {
            Def("a", Step("s", RemediationStepKinds.ClearPath, @"C:\")),
        }), "attack");
        Assert.False(root.Allowed);
    }

    // ---- F12: binding ambiguity — separator-shifted fields cannot collide ----

    [Fact]
    public void F12_Binding_LengthPrefixed_NoSeparatorCollision()
    {
        var def = Def("a", Step("s", RemediationStepKinds.RestartService, "Niagara"));
        var lib = new AutomationLibrary("test-lib", 1, new[] { def });
        var p1 = RemediationBinding.Payload(def, lib, "d|e", "f", "c");
        var p2 = RemediationBinding.Payload(def, lib, "d", "e|f", "c");
        Assert.NotEqual(p1, p2);
        // Separator-bearing ids are refused at admission outright.
        var bad = new AutomationLibrary("bad|lib", 1, new[] { def });
        Assert.NotNull(bad.Validate());
    }
}
