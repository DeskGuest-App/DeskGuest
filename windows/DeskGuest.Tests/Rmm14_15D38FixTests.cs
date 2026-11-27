using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>D38 reconciliation regression tests for RMM-14 + RMM-15
/// (Block R, cross-review packet 1877a640, findings
/// F1–F12). Each test pins the FIXED behaviour and is named
/// D38F&lt;n&gt;_*; several re-attack the fixed surface. No real
/// network: loopback/fake transports only.</summary>
public class Rmm14_15D38FixTests
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

    private static JobStepDefinition Idem(string id) => new(id, id, StepIdempotency.Idempotent);
    private static JobStepDefinition NonIdem(string id) => new(id, id, StepIdempotency.NonIdempotent);

    private static ResumableJob PatchJob(JobJournal j, Auth a, TimeSpan ttl, params JobStepDefinition[] steps) =>
        j.CreateJob(JobKinds.PatchRun, "dev1", steps,
            a.Signer.Sign(SignedCommandClasses.PatchDeploy, Encoding.UTF8.GetBytes("job-payload"), T0, ttl), T0)!;

    private static byte[] Payload(string seed, int size = 200_000)
    {
        var bytes = new byte[size];
        var s = Encoding.UTF8.GetBytes(seed);
        for (var i = 0; i < size; i++) bytes[i] = s[i % s.Length];
        for (var i = 0; i < size; i += 4096) bytes[i] ^= (byte)(i / 4096);
        return bytes;
    }

    // Attacker tool (mirrors the destruction suite): rewrite the
    // exported journal and RECOMPUTE the whole hash chain correctly.
    private static string RecomputeChain(string exportJson, Func<JsonElement, (string Kind, string Detail)> mutate)
    {
        using var doc = JsonDocument.Parse(exportJson);
        var entries = doc.RootElement.EnumerateArray().ToList();
        var sb = new StringBuilder("[");
        var prev = "GENESIS";
        var first = true;
        foreach (var e in entries)
        {
            var seq = e.GetProperty("Seq").GetInt64();
            var jobId = e.GetProperty("JobId").GetString()!;
            var at = e.GetProperty("AtUtc").GetDateTimeOffset();
            var (kind, detail) = mutate(e);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{seq}|{jobId}|{at:O}|{kind}|{detail}|{prev}"))).ToLowerInvariant();
            if (!first) sb.Append(',');
            first = false;
            sb.Append(JsonSerializer.Serialize(new
            {
                Seq = seq, JobId = jobId, AtUtc = at, Kind = kind, Detail = detail,
                PrevHash = prev, Hash = hash, SignatureBase64 = (string?)null,
            }));
            prev = hash;
        }
        return sb.Append(']').ToString();
    }

    // Attacker tool: append ONE entry with a CORRECTLY computed hash
    // (the strongest append short of holding the endpoint key).
    private static string AppendEntry(string exportJson, string jobId, string kind, string detail, DateTimeOffset at)
    {
        using var doc = JsonDocument.Parse(exportJson);
        var entries = doc.RootElement.EnumerateArray().ToList();
        var last = entries[^1];
        var seq = last.GetProperty("Seq").GetInt64() + 1;
        var prev = last.GetProperty("Hash").GetString()!;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{seq}|{jobId}|{at:O}|{kind}|{detail}|{prev}"))).ToLowerInvariant();
        var arr = JsonNode.Parse(exportJson)!.AsArray();
        arr.Add(new JsonObject
        {
            ["Seq"] = seq, ["JobId"] = jobId, ["AtUtc"] = at, ["Kind"] = kind, ["Detail"] = detail,
            ["PrevHash"] = prev, ["Hash"] = hash, ["SignatureBase64"] = null,
        });
        return arr.ToJsonString();
    }

    // ================= F1 — multi-crash resume =================

    [Fact]
    public void D38F1_MultiCrash_AfterHumanRetry_SecondCrash_ParksAgain_NoCompletionWithoutHuman()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("charge"), Idem("receipt"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "charge", T0); // crash #1 mid-effect

        var r1 = new JobJournal(); r1.ImportJson(j.ExportJson());
        r1.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, r1.GetJob(job.Id)!.State);
        Assert.True(r1.ResolveParked(job.Id, ParkedDecision.RetryStep, "tech-1", T0.AddMinutes(6)));
        Assert.Equal(JobStates.Resumed, r1.GetJob(job.Id)!.State);
        Assert.True(r1.BeginStep(job.Id, "charge", T0.AddMinutes(7))); // running again
        // crash #2 — the F1 hole: this journal must NOT be skipped.
        var r2 = new JobJournal(); r2.ImportJson(r1.ExportJson());
        var report = r2.ResumeAll(T0.AddMinutes(10), true, a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var after = r2.GetJob(job.Id)!;
        Assert.Equal(JobStates.Parked, after.State);
        Assert.Equal(StepStates.Uncertain, after.Steps[0].State);
        // and there is NO path to completion without a human:
        Assert.False(r2.BeginStep(job.Id, "charge", T0.AddMinutes(11)));
        Assert.False(r2.CompleteStep(job.Id, "charge", T0.AddMinutes(11)));
        Assert.NotEqual(JobStates.Done, r2.GetJob(job.Id)!.State);
    }

    [Fact]
    public void D38F1_MultiCrash_ResumedJob_ExpiredEnvelope_NowFailsInsteadOfSkipping()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromMinutes(30), NonIdem("charge"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "charge", T0);
        var r1 = new JobJournal(); r1.ImportJson(j.ExportJson());
        r1.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, r1.GetJob(job.Id)!.State);
        Assert.True(r1.ResolveParked(job.Id, ParkedDecision.RetryStep, "tech-1", T0.AddMinutes(6)));
        Assert.True(r1.BeginStep(job.Id, "charge", T0.AddMinutes(7)));
        var r2 = new JobJournal(); r2.ImportJson(r1.ExportJson());
        // the envelope expired during the second outage: the old code
        // reported "already resumed" and let the step complete.
        var report = r2.ResumeAll(T0.AddHours(2), true, a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var after = r2.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, after.State);
        Assert.Equal(JobFailureReasons.AuthorityExpired, after.FailureReason);
        Assert.False(r2.CompleteStep(job.Id, "charge", T0.AddHours(2)));
    }

    [Fact]
    public void D38F1_BeginStep_RefusedCall_MutatesNothing_AndTransitionIsJournalled()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var r = new JobJournal(); r.ImportJson(j.ExportJson());
        r.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Resumed, r.GetJob(job.Id)!.State);
        var entriesBefore = r.Entries.Count;
        // refused calls (out of order, unknown step) change NOTHING:
        Assert.False(r.BeginStep(job.Id, "s2", T0.AddMinutes(6)));
        Assert.False(r.BeginStep(job.Id, "nope", T0.AddMinutes(6)));
        Assert.Equal(entriesBefore, r.Entries.Count);
        Assert.Equal(JobStates.Resumed, r.GetJob(job.Id)!.State);
        // the accepted call journals the Resumed→Running transition:
        Assert.True(r.BeginStep(job.Id, "s1", T0.AddMinutes(7)));
        var kinds = r.Entries.Select(e => e.Kind).ToList();
        var resumedIdx = kinds.LastIndexOf("job_resumed");
        var startedIdx = kinds.FindIndex(resumedIdx, k => k == "job_started");
        var stepIdx = kinds.FindIndex(resumedIdx, k => k == "step_started");
        Assert.True(startedIdx > resumedIdx && stepIdx > startedIdx,
            "job_started must be journalled between job_resumed and step_started");
    }

    [Fact]
    public void D38F1_IdempotentJob_SecondCrashAfterResume_ResumesAgain_DoesNotWedge()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("a-step"), Idem("b-step"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "a-step", T0);
        var r1 = new JobJournal(); r1.ImportJson(j.ExportJson());
        r1.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Resumed, r1.GetJob(job.Id)!.State);
        Assert.True(r1.BeginStep(job.Id, "a-step", T0.AddMinutes(6))); // crash #2 mid-step
        var r2 = new JobJournal(); r2.ImportJson(r1.ExportJson());
        var report = r2.ResumeAll(T0.AddMinutes(10), true, a.Ring);
        Assert.Equal(1, report.ResumedCount);
        var after = r2.GetJob(job.Id)!;
        Assert.Equal(JobStates.Resumed, after.State);
        Assert.Equal(StepStates.Pending, after.Steps[0].State);
        Assert.True(r2.BeginStep(job.Id, "a-step", T0.AddMinutes(11)));
        Assert.True(r2.CompleteStep(job.Id, "a-step", T0.AddMinutes(11)));
        Assert.True(r2.BeginStep(job.Id, "b-step", T0.AddMinutes(12)));
        Assert.True(r2.CompleteStep(job.Id, "b-step", T0.AddMinutes(12)));
        Assert.Equal(JobStates.Done, r2.GetJob(job.Id)!.State);
    }

    // ================= F2 — replay stops at the break =================

    [Fact]
    public void D38F2_ForgedAppendedJobDone_SignedJournal_NeverFakesDone_HubRefusesReport()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var j = new JobJournal(endpoint);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        // forged appended job_done with a CORRECT hash but no valid
        // endpoint signature (the attacker holds no endpoint seed):
        var forged = AppendEntry(j.ExportJson(), job.Id, "job_done", "all steps complete", T0.AddMinutes(1));
        var restored = JobJournal.ForVerification(endpoint.PublicKey);
        var v = restored.ImportJson(forged);
        Assert.False(v.Ok);
        Assert.NotEqual(JobStates.Done, restored.GetJob(job.Id)!.State); // forged terminal state never lands
        var report = restored.BuildStateReport("dev1", true, T0.AddMinutes(2));
        Assert.False(report.ChainOk);
        Assert.NotNull(report.BrokenAtSeq);
        var hub = new JobStateReconciler(() => T0);
        Assert.False(hub.Accept(report).Accepted); // the hub refuses broken-journal state outright
        // and the honest later word (a fresh, intact journal failing
        // the job) is what the hub keeps:
        var honest = new JobJournal(endpoint);
        honest.ImportJson(j.ExportJson());
        honest.ResumeAll(T0.AddMinutes(3), true, a.Ring);
        Assert.True(honest.GetJob(job.Id)!.State == JobStates.Resumed);
    }

    [Fact]
    public void D38F2_Reattack_JobDoneWithOutstandingSteps_ReplayIgnoresIt()
    {
        var a = NewAuth();
        var j = new JobJournal(); // unsigned: chain recompute is possible, so replay itself must refuse
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0); j.CompleteStep(job.Id, "s1", T0);
        var forged = AppendEntry(j.ExportJson(), job.Id, "job_done", "all steps complete", T0.AddMinutes(1));
        var restored = new JobJournal();
        Assert.True(restored.ImportJson(forged).Ok); // chain is internally valid…
        Assert.NotEqual(JobStates.Done, restored.GetJob(job.Id)!.State); // …but done requires ALL steps
        Assert.Equal(JobStates.Running, restored.GetJob(job.Id)!.State);
    }

    // ================= F3 — rollback / truncation =================

    [Fact]
    public void D38F3_RollbackToOlderJournalFile_DetectedAtLoad_NothingResumes()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal(endpoint);
        j.LoadFromFile(path);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("apply"), Idem("verify"));
        j.StartJob(job.Id, T0);
        j.SaveToFile(path);
        var oldFileText = File.ReadAllText(path); // snapshot BEFORE the step runs
        j.BeginStep(job.Id, "apply", T0);          // the non-idempotent step's effect lands
        j.SaveToFile(path);                        // anchor now covers step_started
        File.WriteAllText(path, oldFileText);      // ATTACK: roll the journal file back
        var restored = new JobJournal(endpoint);
        var v = restored.LoadFromFile(path);
        Assert.False(v.Ok);
        Assert.Contains("rollback", v.Summary);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        var after = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, after.State); // NOT pending-and-rerun: the double effect is stopped
        Assert.Equal(JobFailureReasons.JournalTampered, after.FailureReason);
        Assert.False(restored.BeginStep(job.Id, "apply", T0.AddMinutes(6)));
    }

    [Fact]
    public void D38F3_Truncation_ErasingAFailDecision_DetectedAtLoad()
    {
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        Assert.True(j.FailStep(job.Id, "s1", "disk full", T0));
        j.SaveToFile(path);
        // ATTACK: cut the step_failed + job_failed entries off the end:
        var arr = JsonNode.Parse(File.ReadAllText(path))!.AsArray();
        while (arr.Count > 3) arr.RemoveAt(arr.Count - 1);
        File.WriteAllText(path, arr.ToJsonString());
        var restored = new JobJournal();
        var v = restored.LoadFromFile(path);
        Assert.False(v.Ok); // the anchor remembers the longer history
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Failed, restored.GetJob(job.Id)!.State);
        Assert.Equal(JobFailureReasons.JournalTampered, restored.GetJob(job.Id)!.FailureReason);
    }

    [Fact]
    public void D38F3_ImportJson_WithExplicitAnchor_AcceptsCurrent_RefusesShorter()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var (head, seq) = j.CurrentAnchor;
        var full = j.ExportJson();
        Assert.True(new JobJournal().ImportJson(full, head, seq).Ok);
        var arr = JsonNode.Parse(full)!.AsArray();
        arr.RemoveAt(arr.Count - 1);
        var v = new JobJournal().ImportJson(arr.ToJsonString(), head, seq);
        Assert.False(v.Ok);
        Assert.Contains("rollback", v.Summary);
    }

    // ================= F4 — verify-only construction contract =================

    [Fact]
    public void D38F4_VerifyOnlyJournal_NeverAppends_SecondRestartStillVerifies()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var j = new JobJournal(endpoint);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var export = j.ExportJson();
        var verify = JobJournal.ForVerification(endpoint.PublicKey);
        Assert.True(verify.ImportJson(export).Ok);
        var entriesBefore = verify.Entries.Count;
        verify.ResumeAll(T0.AddMinutes(5), true, a.Ring); // in-memory pass only
        Assert.Equal(JobStates.Resumed, verify.GetJob(job.Id)!.State);
        Assert.Equal(entriesBefore, verify.Entries.Count); // NO unsigned entries were appended
        // execution mutations refuse outright on a verify-only journal:
        Assert.False(verify.BeginStep(job.Id, "s1", T0.AddMinutes(6)));
        Assert.False(verify.StartJob(job.Id, T0.AddMinutes(6)));
        Assert.Null(verify.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("x") }, null, T0));
        // the next restart verifies the SAME export cleanly — signed
        // resume no longer works for exactly one restart:
        var verify2 = JobJournal.ForVerification(endpoint.PublicKey);
        Assert.True(verify2.ImportJson(verify.ExportJson()).Ok);
    }

    [Fact]
    public void D38F4_SignedJournal_TwoFullRestartCycles_KeepWorking()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var j = new JobJournal(endpoint);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"), Idem("s2"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var cycle1 = new JobJournal(endpoint);
        Assert.True(cycle1.ImportJson(j.ExportJson()).Ok);
        cycle1.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Resumed, cycle1.GetJob(job.Id)!.State);
        Assert.True(cycle1.BeginStep(job.Id, "s1", T0.AddMinutes(6)));
        Assert.True(cycle1.CompleteStep(job.Id, "s1", T0.AddMinutes(6)));
        var cycle2 = new JobJournal(endpoint);
        Assert.True(cycle2.ImportJson(cycle1.ExportJson()).Ok); // cycle-1 entries are signed too
        cycle2.ResumeAll(T0.AddMinutes(10), true, a.Ring);
        Assert.True(cycle2.BeginStep(job.Id, "s2", T0.AddMinutes(11)));
        Assert.True(cycle2.CompleteStep(job.Id, "s2", T0.AddMinutes(11)));
        Assert.Equal(JobStates.Done, cycle2.GetJob(job.Id)!.State);
    }

    // ================= F5 — write-ahead durability =================

    [Fact]
    public void D38F5_WriteAhead_CrashWithoutAnySave_StepStartedSurvives_ParksNonIdempotent()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal(endpoint);
        j.LoadFromFile(path); // attaches write-ahead persistence
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("apply"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "apply", T0); // effect may have landed; NO SaveToFile ever happens
        // process dies here. The WAL alone must rebuild the journal:
        var restored = new JobJournal(endpoint);
        var v = restored.LoadFromFile(path);
        Assert.True(v.Ok, v.Summary);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        var after = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Parked, after.State); // parked — NOT pending-and-silently-rerun
        Assert.Equal(StepStates.Uncertain, after.Steps[0].State);
    }

    [Fact]
    public void D38F5_TornMainFile_RecoveredFromWriteAheadLog()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal(endpoint);
        j.LoadFromFile(path);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"), NonIdem("apply"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "s1", T0); j.CompleteStep(job.Id, "s1", T0);
        j.SaveToFile(path);
        j.BeginStep(job.Id, "apply", T0);
        File.WriteAllText(path, "TORN{{{not json"); // power loss tears the main store
        var restored = new JobJournal(endpoint);
        var v = restored.LoadFromFile(path);
        Assert.True(v.Ok, v.Summary);
        Assert.Contains("write-ahead", v.Summary);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void D38F5_UnreadableStore_IsNamedJournalLost_NeverSilentlyEmpty()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        File.WriteAllText(path, "garbage{{{");
        var j = new JobJournal();
        var v = j.LoadFromFile(path);
        Assert.False(v.Ok);
        Assert.Equal(JobFailureReasons.JournalLost, j.ImportError);
        var report = j.BuildStateReport("dev1", true, T0);
        Assert.False(report.ChainOk);
        Assert.Contains(JobFailureReasons.JournalLost, report.ChainSummary);
        // missing file with a surviving anchor is journal_lost too:
        var a = NewAuth();
        var dir2 = TestUtil.TempDir();
        var path2 = Path.Combine(dir2, "journal.json");
        var j2 = new JobJournal();
        var job = PatchJob(j2, a, TimeSpan.FromHours(4), Idem("s1"));
        j2.StartJob(job.Id, T0);
        j2.SaveToFile(path2);
        File.Delete(path2);
        var j3 = new JobJournal();
        var v3 = j3.LoadFromFile(path2);
        Assert.False(v3.Ok);
        Assert.Equal(JobFailureReasons.JournalLost, j3.ImportError);
    }

    // ================= F6 — toggle plumbing =================

    [Fact]
    public void D38F6_ResumeToggle_OnePolicySource_BehaviourAndReportAgree()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var export = j.ExportJson();

        var engineOff = new ManagementPolicyEngine();
        engineOff.AddDocument(new ManagementPolicyDocument("off1", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { ["rmm.job_resume.enabled"] = "false" }, 1));
        var facts = StaticDeviceFacts.Of("dev1", "co1");
        Func<bool> toggleOff = () => engineOff.IsEnabled(facts, "rmm.job_resume.enabled");

        var restored = new JobJournal(); restored.ImportJson(export);
        restored.ResumeAll(T0.AddMinutes(5), toggleOff, a.Ring);
        Assert.Equal(JobStates.Failed, restored.GetJob(job.Id)!.State);
        Assert.Equal(JobFailureReasons.ResumeDisabled, restored.GetJob(job.Id)!.FailureReason);
        Assert.False(restored.BuildStateReport("dev1", toggleOff, T0.AddMinutes(6)).ResumeEnabled);

        var engineOn = new ManagementPolicyEngine(); // registry default ON
        Func<bool> toggleOn = () => engineOn.IsEnabled(facts, "rmm.job_resume.enabled");
        var restored2 = new JobJournal(); restored2.ImportJson(export);
        restored2.ResumeAll(T0.AddMinutes(5), toggleOn, a.Ring);
        Assert.Equal(JobStates.Resumed, restored2.GetJob(job.Id)!.State);
        Assert.True(restored2.BuildStateReport("dev1", toggleOn, T0.AddMinutes(6)).ResumeEnabled);
    }

    [Fact]
    public void D38F6_ResolveParked_RespectsTheToggle_FailJobStillAllowed()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("risky"), Idem("later"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "risky", T0);
        var r = new JobJournal(); r.ImportJson(j.ExportJson());
        r.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, r.GetJob(job.Id)!.State);
        // toggle OFF: a resume-ing decision refuses…
        Assert.False(r.ResolveParked(job.Id, ParkedDecision.RetryStep, "tech-1", T0.AddMinutes(6), () => false));
        Assert.Equal(JobStates.Parked, r.GetJob(job.Id)!.State);
        // …but FailJob resumes nothing and stays available:
        Assert.True(r.ResolveParked(job.Id, ParkedDecision.FailJob, "tech-1", T0.AddMinutes(7), () => false));
        Assert.Equal(JobStates.Failed, r.GetJob(job.Id)!.State);
    }

    [Fact]
    public void D38F6_DistributionToggle_EnforcedInFetcher_Serving_AndCoordinator()
    {
        var content = Payload("toggle");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var peerStore = new PeerContentStore(); peerStore.PutVerified(m, content);
        // fetcher refuses under OFF even with a willing source:
        var fetch = new ContentFetcher().Fetch(m,
            new IContentSource[] { new StoreContentSource("peer1", peerStore) },
            distributionEnabled: () => false);
        Assert.False(fetch.Ok);
        Assert.Contains("disabled", fetch.Reason);
        // serving source serves nothing under OFF:
        var gated = new StoreContentSource("peer1", peerStore, servingEnabled: () => false);
        Assert.Null(gated.FetchChunk(m, 0));
        // coordinator admits nothing and offers nothing under OFF:
        var id = NewIdentity();
        var coord = new HubDistributionCoordinator(x => x == "peer1" ? id.PublicKey : null,
            distributionEnabled: () => false);
        var claim = AvailabilityClaim.Sign(id, "peer1", m.ContentHash, false, T0, TimeSpan.FromHours(1));
        Assert.False(coord.AdmitClaim(claim, T0).Accepted);
        Assert.Empty(coord.SourcesFor(m.ContentHash, T0));
    }

    // ================= F7 — availability claims =================

    [Fact]
    public void D38F7_CacheStatus_ComesFromPolicy_NotTheClaim()
    {
        var liar = NewIdentity(); var realCache = NewIdentity();
        var keys = new Dictionary<string, byte[]> { ["liar"] = liar.PublicKey, ["realcache"] = realCache.PublicKey };
        var coord = new HubDistributionCoordinator(id => keys.GetValueOrDefault(id),
            cacheDesignation: id => id == "realcache"); // Effective Policy's answer
        var m = ContentManifest.Build(Payload("c"), chunkSize: 64 * 1024);
        // the liar CLAIMS cache; policy says otherwise:
        Assert.True(coord.AdmitClaim(AvailabilityClaim.Sign(liar, "liar", m.ContentHash, true, T0, TimeSpan.FromHours(1)), T0).Accepted);
        Assert.False(coord.ClaimsFor(m.ContentHash).Single(c => c.DeviceId == "liar").IsCache);
        // the real cache doesn't even claim it; policy designates it:
        Assert.True(coord.AdmitClaim(AvailabilityClaim.Sign(realCache, "realcache", m.ContentHash, false, T0, TimeSpan.FromHours(1)), T0).Accepted);
        Assert.True(coord.ClaimsFor(m.ContentHash).Single(c => c.DeviceId == "realcache").IsCache);
        Assert.Equal(new[] { "realcache", "liar" }, coord.SourcesFor(m.ContentHash, T0.AddMinutes(1)));
    }

    [Fact]
    public void D38F7_UnboundedClaimLifetime_Refused()
    {
        var id = NewIdentity();
        var coord = new HubDistributionCoordinator(x => x == "peer1" ? id.PublicKey : null);
        var m = ContentManifest.Build(Payload("c"), chunkSize: 64 * 1024);
        var claim = AvailabilityClaim.Sign(id, "peer1", m.ContentHash, false, T0, TimeSpan.FromDays(365 * 100));
        Assert.False(claim.VerifySignature(id.PublicKey, T0));
        Assert.False(coord.AdmitClaim(claim, T0).Accepted);
        Assert.Empty(coord.SourcesFor(m.ContentHash, T0));
    }

    [Fact]
    public void D38F7_FutureClaimedUtc_ClampedAtAdmission_DoesNotWinFreshness()
    {
        var aId = NewIdentity(); var bId = NewIdentity();
        var keys = new Dictionary<string, byte[]> { ["devA"] = aId.PublicKey, ["devB"] = bId.PublicKey };
        var coord = new HubDistributionCoordinator(id => keys.GetValueOrDefault(id));
        var m = ContentManifest.Build(Payload("c"), chunkSize: 64 * 1024);
        // devB's claim is dated 4 minutes in the future (inside skew):
        var claimB = AvailabilityClaim.Sign(bId, "devB", m.ContentHash, false, T0.AddMinutes(4), TimeSpan.FromHours(1));
        Assert.True(coord.AdmitClaim(claimB, T0).Accepted);
        Assert.Equal(T0, coord.ClaimsFor(m.ContentHash).Single(c => c.DeviceId == "devB").ClaimedUtc); // clamped
        // devA's honest claim a minute later is genuinely fresher:
        var claimA = AvailabilityClaim.Sign(aId, "devA", m.ContentHash, false, T0.AddMinutes(1), TimeSpan.FromHours(1));
        Assert.True(coord.AdmitClaim(claimA, T0.AddMinutes(1)).Accepted);
        Assert.Equal(new[] { "devA", "devB" }, coord.SourcesFor(m.ContentHash, T0.AddMinutes(2)));
    }

    [Fact]
    public void D38F7_DeEnrolledDevice_ClaimsDieAtUse()
    {
        var id = NewIdentity();
        var enrolled = new Dictionary<string, byte[]> { ["peer1"] = id.PublicKey };
        var coord = new HubDistributionCoordinator(x => enrolled.GetValueOrDefault(x));
        var m = ContentManifest.Build(Payload("c"), chunkSize: 64 * 1024);
        Assert.True(coord.AdmitClaim(AvailabilityClaim.Sign(id, "peer1", m.ContentHash, false, T0, TimeSpan.FromHours(1)), T0).Accepted);
        Assert.Single(coord.SourcesFor(m.ContentHash, T0.AddMinutes(1)));
        enrolled.Remove("peer1"); // de-enrolled AFTER claiming
        Assert.Empty(coord.SourcesFor(m.ContentHash, T0.AddMinutes(2)));
    }

    // ================= F8 — revocation fails closed =================

    private sealed class RevokingSource : IContentSource
    {
        private readonly PeerContentStore _store; private readonly Action _onFetch;
        public RevokingSource(PeerContentStore store, Action onFetch) { _store = store; _onFetch = onFetch; }
        public string SourceId => "revoking-peer";
        public bool IsHub => false;
        public byte[]? FetchChunk(ContentManifest manifest, int index)
        {
            _onFetch();
            return _store.GetChunk(manifest.ContentHash, manifest, index);
        }
    }

    [Fact]
    public void D38F8_LocalStoreRevocation_Consulted_EvenWhenCallerOmitsTheDelegate()
    {
        var content = Payload("revoked-locally");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var sourceStore = new PeerContentStore(); sourceStore.PutVerified(m, content);
        var local = new PeerContentStore();
        local.Revoke(m.ContentHash); // THIS device revoked it; the caller passes no delegate
        var result = new ContentFetcher().Fetch(m,
            new IContentSource[] { new StoreContentSource("peer1", sourceStore) }, local);
        Assert.False(result.Ok);
        Assert.Contains("revoked", result.Reason);
        Assert.Null(result.Content);
    }

    [Fact]
    public void D38F8_RevocationLandingMidFetch_FetchFails_NeverReturnsRevokedBytes()
    {
        var content = Payload("revoked-mid-fetch", 100);
        var m = ContentManifest.Build(content, chunkSize: 1024); // single chunk: exercises the pre-return recheck
        var sourceStore = new PeerContentStore(); sourceStore.PutVerified(m, content);
        var revoked = false;
        var source = new RevokingSource(sourceStore, () => revoked = true);
        var local = new PeerContentStore();
        var result = new ContentFetcher().Fetch(m, new IContentSource[] { source }, local,
            isRevoked: _ => revoked);
        Assert.False(result.Ok);
        Assert.Contains("revoked", result.Reason);
        Assert.Null(result.Content);
        Assert.False(local.Has(m.ContentHash));
    }

    [Fact]
    public void D38F8_RevocationsAndDistrust_PersistAcrossRestart()
    {
        var dir = TestUtil.TempDir();
        var revPath = Path.Combine(dir, "revocations.json");
        var content = Payload("pulled");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var store = new PeerContentStore(revPath);
        store.PutVerified(m, content);
        store.Revoke(m.ContentHash);
        var restarted = new PeerContentStore(revPath); // process restart over the same file
        Assert.True(restarted.IsRevoked(m.ContentHash));
        Assert.False(restarted.Has(m.ContentHash));

        var coord = new HubDistributionCoordinator(_ => null);
        coord.RevokeContent(m.ContentHash);
        coord.ReportDistrustedSource("bad-peer", "lied about chunks", T0);
        var state = coord.ExportStateJson();
        var coord2 = new HubDistributionCoordinator(_ => null);
        coord2.ImportStateJson(state);
        Assert.True(coord2.IsRevoked(m.ContentHash));
        Assert.True(coord2.IsDistrusted("bad-peer", T0.AddMinutes(30)));
        Assert.False(coord2.IsDistrusted("bad-peer", T0.AddHours(25))); // window is bounded, not eternal
    }

    // ================= F9 — hub reconciler =================

    private static JobStateReport Report(string device, DateTimeOffset at, string head, long seq,
        params JobStateSummary[] jobs) =>
        new(device, at, true, head, jobs, ChainOk: true, BrokenAtSeq: null, ChainSummary: "OK", JournalSeq: seq);

    private static JobStateSummary Summary(string id, string state, int done, int resumes) =>
        new(id, JobKinds.PatchRun, state, null, done, 2, resumes);

    [Fact]
    public void D38F9_FutureDatedReport_Refused_AndDeviceIsNotFrozen()
    {
        var hub = new JobStateReconciler(() => T0);
        Assert.True(hub.Accept(Report("dev1", T0, "H1", 1, Summary("j1", JobStates.Running, 0, 0))).Accepted);
        var future = hub.Accept(Report("dev1", new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "H2", 2,
            Summary("j1", JobStates.Running, 0, 0)));
        Assert.False(future.Accepted);
        // a later GENUINE report still lands — the device is not frozen:
        Assert.True(hub.Accept(Report("dev1", T0.AddMinutes(1), "H3", 3, Summary("j1", JobStates.Done, 2, 0))).Accepted);
        Assert.Equal(JobStates.Done, hub.GetJob("dev1", "j1")!.State);
    }

    [Fact]
    public void D38F9_NonTerminalRegressions_Refused_ForwardEdgesAccepted()
    {
        // completed-steps regression (running → running, 1 → 0):
        var hub1 = new JobStateReconciler(() => T0);
        Assert.True(hub1.Accept(Report("d", T0, "H1", 1, Summary("j", JobStates.Running, 1, 1))).Accepted);
        Assert.False(hub1.Accept(Report("d", T0.AddMinutes(1), "H2", 2, Summary("j", JobStates.Running, 0, 1))).Accepted);
        // resumed → pending:
        var hub2 = new JobStateReconciler(() => T0);
        Assert.True(hub2.Accept(Report("d", T0, "H1", 1, Summary("j", JobStates.Resumed, 0, 1))).Accepted);
        Assert.False(hub2.Accept(Report("d", T0.AddMinutes(1), "H2", 2, Summary("j", JobStates.Pending, 0, 1))).Accepted);
        // parked → running (skips the human decision):
        var hub3 = new JobStateReconciler(() => T0);
        Assert.True(hub3.Accept(Report("d", T0, "H1", 1, Summary("j", JobStates.Parked, 0, 0))).Accepted);
        Assert.False(hub3.Accept(Report("d", T0.AddMinutes(1), "H2", 2, Summary("j", JobStates.Running, 0, 0))).Accepted);
        // parked → resumed IS a forward edge (the human decided):
        Assert.True(hub3.Accept(Report("d", T0.AddMinutes(2), "H3", 3, Summary("j", JobStates.Resumed, 0, 1))).Accepted);
        // journal sequence regression:
        var hub4 = new JobStateReconciler(() => T0);
        Assert.True(hub4.Accept(Report("d", T0, "H9", 9, Summary("j", JobStates.Running, 0, 0))).Accepted);
        Assert.False(hub4.Accept(Report("d", T0.AddMinutes(1), "H8", 8, Summary("j", JobStates.Running, 0, 0))).Accepted);
    }

    [Fact]
    public void D38F9_BrokenChainReport_Refused_ForgedTerminalCannotLockIn()
    {
        var hub = new JobStateReconciler(() => T0);
        var forged = new JobStateReport("dev1", T0, true, "FORGEDHEAD",
            new[] { Summary("j1", JobStates.Done, 2, 0) },
            ChainOk: false, BrokenAtSeq: 4, ChainSummary: "BROKEN at seq 4", JournalSeq: 9);
        Assert.False(hub.Accept(forged).Accepted);
        Assert.Null(hub.GetJob("dev1", "j1")); // nothing entered the hub view
        // the honest word afterwards is still admissible:
        Assert.True(hub.Accept(Report("dev1", T0.AddMinutes(1), "HREAL", 5,
            Summary("j1", JobStates.Failed, 0, 0))).Accepted);
        Assert.Equal(JobStates.Failed, hub.GetJob("dev1", "j1")!.State);
    }

    // ================= F10 — fetcher bounds =================

    private sealed class OversizeSource : IContentSource
    {
        public string SourceId => "oversize-peer";
        public bool IsHub => false;
        public int Calls;
        public byte[]? FetchChunk(ContentManifest manifest, int index) { Calls++; return new byte[1_000_000]; }
        // a contract violator: overrides the bounded method and
        // STILL returns the attacker-sized array:
        public byte[]? FetchChunk(ContentManifest manifest, int index, int maxBytes, CancellationToken ct)
        { Calls++; return new byte[1_000_000]; }
    }

    private sealed class SilentSource : IContentSource
    {
        public string SourceId => "silent-peer";
        public bool IsHub => false;
        public byte[]? FetchChunk(ContentManifest manifest, int index)
        {
            Thread.Sleep(3000); // never answers usefully within any sane window
            return null;
        }
    }

    [Fact]
    public void D38F10_OversizeChunks_WasteCappedAtExpectedLength_FailsOverToHub()
    {
        var content = Payload("real");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var evil = new OversizeSource();
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            evil, new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("hub", result.SourceUsed);
        var wasted = result.WastedBytesBySource.GetValueOrDefault("oversize-peer");
        Assert.True(wasted <= (ContentFetcher.DefaultMaxFailedChunksPerSource + 1) * m.ChunkSize,
            $"wasted {wasted} exceeds the expected-length bound");
        Assert.True(wasted < 1_000_000, "attacker-sized arrays must not inflate waste accounting");
    }

    [Fact]
    public void D38F10_SilentPeer_TimesOutPerChunk_FailsOverToHub()
    {
        var content = Payload("real");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var sw = Stopwatch.StartNew();
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            new SilentSource(), new StoreContentSource("hub", hubStore, isHub: true),
        }, chunkTimeout: TimeSpan.FromMilliseconds(250));
        sw.Stop();
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("hub", result.SourceUsed);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2.5),
            $"fetch took {sw.Elapsed} — a silent peer wedged it");
    }

    [Fact]
    public void D38F10_BudgetExhaustion_ReportedToCoordinator_DistrustStopsOffering()
    {
        var liar = NewIdentity();
        var keys = new Dictionary<string, byte[]> { ["liar1"] = liar.PublicKey };
        var coord = new HubDistributionCoordinator(id => keys.GetValueOrDefault(id));
        var content = Payload("real");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        Assert.True(coord.AdmitClaim(AvailabilityClaim.Sign(liar, "liar1", m.ContentHash, false, T0, TimeSpan.FromHours(1)), T0).Accepted);
        Assert.Single(coord.SourcesFor(m.ContentHash, T0));
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var emptyLiar = new PeerContentStore(); // holds nothing: every chunk faults
        var reported = new List<string>();
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            new StoreContentSource("liar1", emptyLiar),
            new StoreContentSource("hub", hubStore, isHub: true),
        }, onSourceDistrusted: (id, reason) =>
        {
            reported.Add(id);
            coord.ReportDistrustedSource(id, reason, T0);
        });
        Assert.True(result.Ok);
        Assert.Contains("liar1", reported);
        Assert.True(coord.IsDistrusted("liar1", T0.AddMinutes(5)));
        Assert.Empty(coord.SourcesFor(m.ContentHash, T0.AddMinutes(5))); // no longer offered — the lie stops costing
    }

    // ================= F11 — crash vs reconnect =================

    [Fact]
    public void D38F11_LiveJournal_ResumeAll_LeavesExecutingStepsAlone_PostImportPassParks()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("apply"), Idem("verify"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "apply", T0); // step executing IN THIS PROCESS
        // a transport reconnect fires ResumeAll on the LIVE journal:
        var live = j.ResumeAll(T0.AddMinutes(1), true, a.Ring);
        Assert.Equal("executing", live.Outcomes.Single(o => o.JobId == job.Id).Outcome);
        var still = j.GetJob(job.Id)!;
        Assert.Equal(JobStates.Running, still.State);       // not parked
        Assert.Equal(StepStates.Running, still.Steps[0].State); // not reset
        Assert.True(j.CompleteStep(job.Id, "apply", T0.AddMinutes(2))); // the in-flight run completes normally
        // contrast: the SAME journal state after a process restart
        // (fresh import, nothing executing) parks as designed:
        var j2 = new JobJournal();
        var job2 = PatchJob(j2, a, TimeSpan.FromHours(4), NonIdem("apply"));
        j2.StartJob(job2.Id, T0); j2.BeginStep(job2.Id, "apply", T0);
        var restored = new JobJournal(); restored.ImportJson(j2.ExportJson());
        var post = restored.ResumeAll(T0.AddMinutes(1), true, a.Ring);
        Assert.Equal("parked", post.Outcomes.Single(o => o.JobId == job2.Id).Outcome);
    }

    // ================= F12 — authority binding at creation/replay =================

    [Fact]
    public void D38F12_CreateJob_WithRing_ForgedOrTamperedEnvelope_Refused()
    {
        var a = NewAuth();
        var other = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("job-payload"), T0, TimeSpan.FromHours(2));
        // ring that does not hold the signing key:
        Assert.Null(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, env, T0, other.Ring));
        // tampered expiry (signature no longer covers the body):
        var tampered = env with { ExpiresUtc = T0.AddYears(1) };
        Assert.Null(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, tampered, T0, a.Ring));
        // the genuine envelope under its own ring:
        Assert.NotNull(j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, env, T0, a.Ring));
    }

    [Fact]
    public void D38F12_FileTransferJob_UnknownClassEnvelope_Refused_KnownClassAccepted()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes("p"), T0, TimeSpan.FromHours(1));
        var bogus = env with { CommandClass = "bogus_class" };
        Assert.Null(j.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("s1") }, bogus, T0));
        Assert.NotNull(j.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("s1") }, env, T0));
    }

    [Fact]
    public void D38F12_Replay_KindClassRebind_CreatesNoJob()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        var forged = RecomputeChain(j.ExportJson(), e =>
        {
            var kind = e.GetProperty("Kind").GetString()!;
            var detail = e.GetProperty("Detail").GetString()!;
            if (kind != "job_created") return (kind, detail);
            var node = JsonNode.Parse(detail)!.AsObject();
            node["envelopeClass"] = "package_deploy"; // rebind patch_run → package_deploy
            return (kind, node.ToJsonString());
        });
        var restored = new JobJournal();
        Assert.True(restored.ImportJson(forged).Ok); // unsigned chain recomputes cleanly…
        Assert.Null(restored.GetJob(job.Id));        // …but the rebind creates no job
    }

    [Fact]
    public void D38F12_CustomerKeyRotationMidJob_ResumeFailsWithTheNamedReason()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        var restored = new JobJournal(); restored.ImportJson(j.ExportJson());
        // the customer rotates mid-job; grace is 10 minutes:
        var newCustomer = NewIdentity();
        a.Ring.Rotate(newCustomer.PublicKey, T0.AddMinutes(5), TimeSpan.FromMinutes(10));
        var report = restored.ResumeAll(T0.AddMinutes(30), true, a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var after = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, after.State);
        Assert.Equal(JobFailureReasons.AuthorityKeyRotated, after.FailureReason); // named, not a bare "invalid"
    }

    // ============ Recovery-lane re-attacks (2026-11-21) ============
    // The D38 fix lane died before running anything; the recovery
    // lane re-attacked the fixed surfaces and found three breaks in
    // the fixes themselves. Each test below FAILED against the dead
    // lane's code and passes against the corrected code.

    [Fact]
    public void D38F12_Reattack_FileTransferWithKnownClassEnvelope_SurvivesReplay()
    {
        // The fix's replay binding demanded envelopeClass ==
        // requiredClass STRICTLY, so a FileTransfer job carrying a
        // known-class envelope (accepted at creation, see
        // D38F12_FileTransferJob_*) VANISHED on import. Replay must
        // mirror creation exactly.
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes("p"), T0, TimeSpan.FromHours(1));
        var job = j.CreateJob(JobKinds.FileTransfer, "dev1", new[] { Idem("s1") }, env, T0);
        Assert.NotNull(job);
        var restored = new JobJournal();
        Assert.True(restored.ImportJson(j.ExportJson()).Ok);
        Assert.NotNull(restored.GetJob(job!.Id));
        // and the rebind attack still creates no job:
        var rebound = RecomputeChain(j.ExportJson(), e =>
        {
            var kind = e.GetProperty("Kind").GetString()!;
            var detail = e.GetProperty("Detail").GetString()!;
            if (kind != "job_created") return (kind, detail);
            var node = JsonNode.Parse(detail)!.AsObject();
            node["envelopeClass"] = "bogus_class";
            return (kind, node.ToJsonString());
        });
        var restored2 = new JobJournal();
        Assert.True(restored2.ImportJson(rebound).Ok);
        Assert.Null(restored2.GetJob(job.Id));
    }

    [Fact]
    public void D38F3_Reattack_WalRecovery_BelowTheAnchor_IsNotARecovery()
    {
        // The fix's WAL-only recovery path never consulted the
        // rollback anchor: tear the main file AND truncate the WAL
        // below the anchor and the rolled-back history verified OK
        // — the erased step_started (non-idempotent effect may have
        // landed) came back as Pending, ready to double-run.
        var endpoint = NewIdentity();
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal(endpoint);
        j.LoadFromFile(path);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("apply"));
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "apply", T0);
        j.SaveToFile(path); // anchor covers seq 3 incl. step_started
        File.WriteAllText(path, "TORN{{{not json");
        var walLines = File.ReadAllLines(path + ".wal");
        Assert.True(walLines.Length >= 3);
        File.WriteAllLines(path + ".wal", walLines.Take(2)); // erase step_started from the WAL too
        var restored = new JobJournal(endpoint);
        var v = restored.LoadFromFile(path);
        Assert.False(v.Ok); // rollback named, never a clean recovery
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        var after = restored.GetJob(job.Id);
        Assert.True(after is null || after.State == JobStates.Failed,
            $"job must fail closed, got {after?.State}");
        Assert.False(restored.BeginStep(job.Id, "apply", T0.AddMinutes(6)));
    }

    [Fact]
    public void D38F5_Reattack_TornMain_WalAtOrAboveAnchor_StillRecovers()
    {
        // The anchor check on the WAL path must not break the
        // legitimate recovery: WAL complete (contains the anchored
        // head), main torn — recovery still verifies OK and the
        // non-idempotent step parks.
        var endpoint = NewIdentity();
        var a = NewAuth();
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "journal.json");
        var j = new JobJournal(endpoint);
        j.LoadFromFile(path);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), NonIdem("apply"));
        j.StartJob(job.Id, T0);
        j.SaveToFile(path);              // anchor at seq 2
        j.BeginStep(job.Id, "apply", T0); // WAL-only entry, seq 3
        File.WriteAllText(path, "TORN{{{not json");
        var restored = new JobJournal(endpoint);
        var v = restored.LoadFromFile(path);
        Assert.True(v.Ok, v.Summary);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void D38F11_Reattack_LiveResumeAll_AlreadyResumedJob_IsNotReAdjudicated()
    {
        // The fix's live-journal guard covered only Running jobs: an
        // already-Resumed job on a live journal fell through to the
        // full gauntlet, so a reconnect after its envelope expired
        // FAILED a legitimately resumed job, and every reconnect
        // inflated ResumeCount + appended job_resumed.
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("p"), T0, TimeSpan.FromMinutes(30));
        var jobA = j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("a1") }, env, T0)!;
        var jobB = j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("b1") }, env, T0)!;
        j.StartJob(jobA.Id, T0); j.BeginStep(jobA.Id, "a1", T0);
        j.StartJob(jobB.Id, T0); j.BeginStep(jobB.Id, "b1", T0);
        var r = new JobJournal(); r.ImportJson(j.ExportJson());
        r.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(1, r.GetJob(jobB.Id)!.ResumeCount);
        Assert.True(r.BeginStep(jobA.Id, "a1", T0.AddMinutes(6))); // journal now LIVE
        var entriesBefore = r.Entries.Count;
        var report = r.ResumeAll(T0.AddHours(2), true, a.Ring); // reconnect, envelope expired since
        var b = r.GetJob(jobB.Id)!;
        Assert.Equal(JobStates.Resumed, b.State);
        Assert.Equal(1, b.ResumeCount);
        Assert.Equal(entriesBefore, r.Entries.Count);
        Assert.Equal("executing", report.Outcomes.Single(o => o.JobId == jobA.Id).Outcome);
        Assert.Equal("already_resumed", report.Outcomes.Single(o => o.JobId == jobB.Id).Outcome);
    }

    [Fact]
    public void D38F2_Reattack_BrokenChainFailure_HoldsPerPass_AndHubRefusesThroughout()
    {
        // Pins the examined-and-held behaviour: the journal_tampered
        // failure on a broken chain is applied in memory on every
        // pass (not journalled onto a distrusted chain), and the
        // hub refuses the broken journal's report regardless.
        var endpoint = NewIdentity();
        var a = NewAuth();
        var j = new JobJournal(endpoint);
        var job = PatchJob(j, a, TimeSpan.FromHours(4), Idem("s1"));
        j.StartJob(job.Id, T0);
        var forged = j.ExportJson().Replace("resumeCount=0", "resumeCount=9");
        Assert.NotEqual(j.ExportJson(), forged);
        var r = new JobJournal(endpoint);
        Assert.False(r.ImportJson(forged).Ok);
        r.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Failed, r.GetJob(job.Id)!.State);
        Assert.Equal(JobFailureReasons.JournalTampered, r.GetJob(job.Id)!.FailureReason);
        var report = r.BuildStateReport("dev1", true, T0.AddMinutes(6));
        Assert.False(report.ChainOk);
        Assert.False(new JobStateReconciler(() => T0.AddMinutes(6)).Accept(report).Accepted);
    }
}
