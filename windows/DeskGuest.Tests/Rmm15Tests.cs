using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-15 — Job resume-on-reconnect. Test names cite the requirement.
public class Rmm15Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private sealed record Auth(DeviceIdentity Customer, SignedCommandSigner Signer, CustomerCommandKeyRing Ring);
    private static Auth NewAuth()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        return new Auth(customer, new SignedCommandSigner(customer), ring);
    }

    private static SignedCommandEnvelope Env(Auth a, string cls, TimeSpan ttl, DateTimeOffset at) =>
        a.Signer.Sign(cls, Encoding.UTF8.GetBytes("job-payload"), at, ttl);

    private static JobStepDefinition Idem(string id) => new(id, id, StepIdempotency.Idempotent);
    private static JobStepDefinition NonIdem(string id) => new(id, id, StepIdempotency.NonIdempotent);

    private static ResumableJob PatchJob(JobJournal j, Auth a, params JobStepDefinition[] steps) =>
        j.CreateJob(JobKinds.PatchRun, "dev1", steps,
            Env(a, SignedCommandClasses.PatchDeploy, TimeSpan.FromHours(2), T0), T0)!;

    [Fact]
    public void RMM15_CreateJob_Validation_UnknownKind_MissingOrWrongEnvelope_ExpiredEnvelope_Refuse()
    {
        var a = NewAuth(); var j = new JobJournal();
        Assert.Null(j.CreateJob("teleport", "dev1", new[] { Idem("s1") }, null, T0));
        // patch_run REQUIRES an envelope (it is a signed-command kind):
        Assert.Null(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, null, T0));
        // wrong class for the kind refuses:
        Assert.Null(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") },
            Env(a, SignedCommandClasses.PackageDeploy, TimeSpan.FromHours(1), T0), T0));
        // already-expired envelope refuses:
        Assert.Null(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") },
            Env(a, SignedCommandClasses.PatchDeploy, TimeSpan.FromMinutes(5), T0.AddHours(-1)), T0));
        // no steps / duplicate step ids refuse:
        Assert.Null(j.CreateJob(JobKinds.FileTransfer, "dev1", Array.Empty<JobStepDefinition>(), null, T0));
        Assert.Null(j.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("s1"), Idem("s1") }, null, T0));
        // file transfer needs no envelope (standing "use" grant is its authority):
        Assert.NotNull(j.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("s1") }, null, T0));
    }

    [Fact]
    public void RMM15_HappyPath_OrderedSteps_DoneRequiresAllSteps()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("download"), Idem("apply"), Idem("verify"));
        Assert.Equal(JobStates.Pending, job.State);
        // out-of-order and not-running acts refuse:
        Assert.False(j.BeginStep(job.Id, "download", T0));
        Assert.True(j.StartJob(job.Id, T0));
        Assert.False(j.BeginStep(job.Id, "apply", T0)); // download not done
        Assert.True(j.BeginStep(job.Id, "download", T0));
        Assert.False(j.CompleteStep(job.Id, "apply", T0)); // not running
        Assert.True(j.CompleteStep(job.Id, "download", T0));
        Assert.NotEqual(JobStates.Done, j.GetJob(job.Id)!.State); // done requires ALL steps
        Assert.True(j.BeginStep(job.Id, "apply", T0));
        Assert.True(j.CompleteStep(job.Id, "apply", T0));
        Assert.True(j.BeginStep(job.Id, "verify", T0));
        Assert.True(j.CompleteStep(job.Id, "verify", T0));
        var done = j.GetJob(job.Id)!;
        Assert.Equal(JobStates.Done, done.State);
        Assert.Equal(3, done.CompletedSteps);
        // terminal: nothing moves a done job
        Assert.False(j.StartJob(job.Id, T0));
        Assert.True(j.Verification.Ok);
    }

    [Fact]
    public void RMM15_CrashMidStep_IdempotentStep_ResumesAndCompletes()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("download"), Idem("apply"), Idem("verify"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "download", T0); j.CompleteStep(job.Id, "download", T0);
        j.BeginStep(job.Id, "apply", T0); // <-- crash here, step mid-flight

        var restored = new JobJournal();
        Assert.True(restored.ImportJson(j.ExportJson()).Ok);
        var report = restored.ResumeAll(T0.AddMinutes(10), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(1, report.ResumedCount);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Resumed, r.State);
        Assert.Equal(1, r.ResumeCount);
        Assert.Equal(StepStates.Done, r.Steps[0].State);       // finished work stays finished
        Assert.Equal(StepStates.Pending, r.Steps[1].State);    // idempotent step safely reset
        // and the job runs to completion after resume:
        Assert.True(restored.BeginStep(job.Id, "apply", T0.AddMinutes(11)));
        Assert.True(restored.CompleteStep(job.Id, "apply", T0.AddMinutes(11)));
        Assert.True(restored.BeginStep(job.Id, "verify", T0.AddMinutes(12)));
        Assert.True(restored.CompleteStep(job.Id, "verify", T0.AddMinutes(12)));
        Assert.Equal(JobStates.Done, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM15_CrashBetweenSteps_ResumesAtNextStep()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"), NonIdem("s2"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "s1", T0); j.CompleteStep(job.Id, "s1", T0);
        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        var report = restored.ResumeAll(T0.AddMinutes(5), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(1, report.ResumedCount);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Resumed, r.State);
        Assert.Equal(StepStates.Pending, r.Steps[1].State); // non-idempotent but never started: safe
    }

    [Fact]
    public void RMM15_NonIdempotentMidFlight_ParksForHuman_NeverGuesses()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"), NonIdem("charge-card"), Idem("s3"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "s1", T0); j.CompleteStep(job.Id, "s1", T0);
        j.BeginStep(job.Id, "charge-card", T0); // crash mid-effect

        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        var report = restored.ResumeAll(T0.AddMinutes(5), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Parked, r.State);
        Assert.Equal(JobFailureReasons.NonIdempotentUncertain, r.FailureReason);
        Assert.Equal(StepStates.Uncertain, r.Steps[1].State);
        // a parked job cannot be started or stepped around the human:
        Assert.False(restored.StartJob(job.Id, T0.AddMinutes(6)));
        Assert.False(restored.BeginStep(job.Id, "s3", T0.AddMinutes(6)));
        // human decides RETRY: step returns to pending, job resumes:
        Assert.True(restored.ResolveParked(job.Id, ParkedDecision.RetryStep, "tech-1", T0.AddMinutes(7)));
        r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Resumed, r.State);
        Assert.Equal(StepStates.Pending, r.Steps[1].State);
        Assert.True(restored.BeginStep(job.Id, "charge-card", T0.AddMinutes(8)));
        Assert.True(restored.CompleteStep(job.Id, "charge-card", T0.AddMinutes(8)));
        Assert.True(restored.BeginStep(job.Id, "s3", T0.AddMinutes(9)));
        Assert.True(restored.CompleteStep(job.Id, "s3", T0.AddMinutes(9)));
        Assert.Equal(JobStates.Done, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM15_ParkedJob_HumanSkip_AndHumanFail_Paths()
    {
        var a = NewAuth();
        // SKIP: human asserts the effect already happened.
        var j1 = new JobJournal();
        var job1 = PatchJob(j1, a, NonIdem("only-step"));
        j1.StartJob(job1.Id, T0); j1.BeginStep(job1.Id, "only-step", T0);
        var r1 = new JobJournal(); r1.ImportJson(j1.ExportJson());
        r1.ResumeAll(T0.AddMinutes(1), true, a.Ring);
        Assert.Equal(JobStates.Parked, r1.GetJob(job1.Id)!.State);
        Assert.True(r1.ResolveParked(job1.Id, ParkedDecision.SkipStep, "tech-1", T0.AddMinutes(2)));
        Assert.Equal(JobStates.Done, r1.GetJob(job1.Id)!.State); // all steps done/skipped

        // FAIL: human ends it.
        var j2 = new JobJournal();
        var job2 = PatchJob(j2, a, NonIdem("only-step"), Idem("later"));
        j2.StartJob(job2.Id, T0); j2.BeginStep(job2.Id, "only-step", T0);
        var r2 = new JobJournal(); r2.ImportJson(j2.ExportJson());
        r2.ResumeAll(T0.AddMinutes(1), true, a.Ring);
        Assert.True(r2.ResolveParked(job2.Id, ParkedDecision.FailJob, "tech-1", T0.AddMinutes(2)));
        var f = r2.GetJob(job2.Id)!;
        Assert.Equal(JobStates.Failed, f.State);
        Assert.Equal(JobFailureReasons.HumanDecisionFail, f.FailureReason);
    }

    [Fact]
    public void RMM15_ExpiredEnvelope_DoesNotSilentlyContinue_ParksAsAuthorityExpired()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = j.CreateJob(JobKinds.UpdateStaging, "dev1", new[] { Idem("stage") },
            Env(a, SignedCommandClasses.UpdateStaging, TimeSpan.FromMinutes(30), T0), T0)!;
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "stage", T0);
        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        // the outage outlasts the envelope:
        var report = restored.ResumeAll(T0.AddHours(2), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, r.State);
        Assert.Equal(JobFailureReasons.AuthorityExpired, r.FailureReason);
    }

    [Fact]
    public void RMM15_ToggleOff_JobsFailResumeDisabled_NamedInState()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        restored.ResumeAll(T0.AddMinutes(5), resumeEnabled: false, ring: a.Ring);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, r.State);
        Assert.Equal(JobFailureReasons.ResumeDisabled, r.FailureReason);
        var stateReport = restored.BuildStateReport("dev1", resumeEnabled: false, T0.AddMinutes(6));
        Assert.False(stateReport.ResumeEnabled); // the OFF state is named in the hub report too
    }

    [Fact]
    public void RMM15_PendingJob_IsNotFalselyLabelledResumed()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"));
        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        var report = restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(0, report.ResumedCount);
        Assert.Equal(JobStates.Pending, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM15_FailedStep_FailsJobWithReason()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        Assert.True(j.FailStep(job.Id, "s1", "disk full", T0));
        var r = j.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, r.State);
        Assert.Contains("step_failed:s1:disk full", r.FailureReason);
    }

    [Fact]
    public void RMM15_HubReport_AndReconciler_ForwardOnly()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"));
        j.StartJob(job.Id, T0);
        var hub = new JobStateReconciler();
        var rep1 = j.BuildStateReport("dev1", true, T0.AddMinutes(1));
        Assert.True(hub.Accept(rep1).Accepted);
        Assert.Equal(JobStates.Running, hub.GetJob("dev1", job.Id)!.State);
        j.BeginStep(job.Id, "s1", T0.AddMinutes(2)); j.CompleteStep(job.Id, "s1", T0.AddMinutes(2));
        var rep2 = j.BuildStateReport("dev1", true, T0.AddMinutes(3));
        Assert.True(hub.Accept(rep2).Accepted);
        Assert.Equal(JobStates.Done, hub.GetJob("dev1", job.Id)!.State);
    }

    [Fact]
    public void RMM15_FilePersistence_RoundTrips_ThroughCrash()
    {
        var a = NewAuth(); var j = new JobJournal();
        var job = PatchJob(j, a, Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0); j.CompleteStep(job.Id, "s1", T0);
        var path = Path.Combine(TestUtil.TempDir(), "journal.json");
        j.SaveToFile(path);
        var restored = new JobJournal();
        Assert.True(restored.LoadFromFile(path).Ok);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Resumed, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM15_SignedJournal_RoundTrips_AndVerifies()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var j = new JobJournal(endpoint);
        var job = PatchJob(j, a, Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var restored = JobJournal.ForVerification(endpoint.PublicKey);
        Assert.True(restored.ImportJson(j.ExportJson()).Ok);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Resumed, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM15_ScriptChainAndBackupKinds_MapToTheirSignedClasses()
    {
        var a = NewAuth(); var j = new JobJournal();
        Assert.NotNull(j.CreateJob(JobKinds.ScriptChain, "dev1", new[] { Idem("run") },
            Env(a, SignedCommandClasses.ScriptExec, TimeSpan.FromHours(1), T0), T0));
        Assert.NotNull(j.CreateJob(JobKinds.Backup, "dev1", new[] { Idem("snap") },
            Env(a, SignedCommandClasses.Automation, TimeSpan.FromHours(1), T0), T0));
        Assert.NotNull(j.CreateJob(JobKinds.Deployment, "dev1", new[] { Idem("install") },
            Env(a, SignedCommandClasses.PackageDeploy, TimeSpan.FromHours(1), T0), T0));
    }
}
