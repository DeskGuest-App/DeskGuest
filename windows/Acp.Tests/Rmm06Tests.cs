using System.Text;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Core.Services;

namespace Acp.Tests;

// RMM-06 — Endpoint backup to user-owned storage. Test names cite
// the requirement. Fakes only: no real disk is captured, snapshotted
// or restored anywhere in this file.
public class Rmm06Tests
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

    private static SignedCommandEnvelope Env(Auth a, string payload, DateTimeOffset at, TimeSpan? ttl = null) =>
        a.Signer.Sign(SignedCommandClasses.Automation, Encoding.UTF8.GetBytes(payload), at, ttl ?? TimeSpan.FromHours(2));

    private static BackupJobDefinition FileJob(string id = "job1", string device = "dev1", string owner = "alice",
        string target = "nas1", int retentionDays = 7, params string[] selection) => new(
            id, device, owner, BackupKinds.File,
            selection.Length > 0 ? selection : new[] { @"C:\data\a.txt", @"C:\data\b.txt" },
            target, new BackupSchedule(24), retentionDays, true);

    private sealed record Rig(BackupSnapshotStore Store, InMemoryBackupStorage Raw, FakeBackupCaptureSource Capture,
        ChainedAuditLog Audit, BackupEngine Engine, Auth Auth);

    private static Rig NewRig(JobJournal? journal = null, bool withVerifier = true, Func<string, bool>? policyGate = null)
    {
        var auth = NewAuth();
        var raw = new InMemoryBackupStorage();
        var verifier = withVerifier ? new SignedCommandVerifier(auth.Ring) : null;
        var store = new BackupSnapshotStore("nas1", raw, verifier);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha")
            .AddFile(@"C:\data\b.txt", "beta");
        var audit = new ChainedAuditLog();
        var engine = new BackupEngine(store, capture, audit, journal, verifier, policyGate);
        return new Rig(store, raw, capture, audit, engine, auth);
    }

    private static JobJournal NewJournal(Auth a) => new(NewIdentity(), null);

    // ---- targets ---------------------------------------------------

    [Fact]
    public void RMM06_TargetValidation_UserOwnedShapes_Admitted()
    {
        Assert.Null(new BackupStorageTarget("t1", BackupTargetKinds.Local, @"D:\backups").Validate());
        Assert.Null(new BackupStorageTarget("t2", BackupTargetKinds.Nas, @"\\filer01\backups").Validate());
        Assert.Null(new BackupStorageTarget("t3", BackupTargetKinds.SiteServer, "smb://site-server/share").Validate());
        Assert.Null(new BackupStorageTarget("t4", BackupTargetKinds.Hub, "hub-device-01").Validate());
    }

    [Fact]
    public void RMM06_NormaliseRelative_KeepsDriveSeparatorSlash()
    {
        // Regression: the drive-relative form dropped its slash and
        // produced "Cdata/a.txt", which no restore request could
        // ever name — found by the self-restore test, kept here.
        Assert.Equal("C/data/a.txt", FakeBackupCaptureSource.NormaliseRelative(@"C:\data\a.txt"));
        Assert.Equal("D/x/y.bin", FakeBackupCaptureSource.NormaliseRelative("D:/x/y.bin"));
    }

    [Fact]
    public void RMM06_TargetValidation_CloudShapes_AndBadShapes_Refused()
    {
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Local, "backups\\relative").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Local, @"C:backups").Validate()); // drive-relative is not absolute
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Hub, "https://hub.example.com").Validate());
        Assert.NotNull(new BackupStorageTarget("t", "cloud", @"\\filer01\backups").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, "https://filer01/backups").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, "filer01/backups").Validate());
    }

    // ---- policy content ---------------------------------------------

    private static EffectivePolicy EffectiveWith(Dictionary<string, string> settings)
    {
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddDocument(new ManagementPolicyDocument(
            "doc1", PolicyLevels.Org, "scope1", settings, 1));
        Assert.True(verdict.Allowed, verdict.Reason);
        return engine.ComputeEffective(StaticDeviceFacts.Of("dev1", "scope1"));
    }

    private static Dictionary<string, string> GoodPolicySettings() => new()
    {
        ["backup.targets"] = "nas1",
        ["backup.target.nas1.kind"] = "nas",
        ["backup.target.nas1.locator"] = @"\\filer01\backups",
        ["backup.jobs"] = "job1",
        ["backup.job.job1.device"] = "dev1",
        ["backup.job.job1.owner"] = "alice",
        ["backup.job.job1.kind"] = "file",
        ["backup.job.job1.selection"] = @"C:\data\a.txt;C:\data\b.txt",
        ["backup.job.job1.target"] = "nas1",
        ["backup.job.job1.interval_hours"] = "24",
        ["backup.job.job1.retention_days"] = "7",
    };

    [Fact]
    public void RMM06_PolicyContent_Parses_JobsTargetsSchedulesRetention()
    {
        var parsed = BackupPolicyContent.Parse(EffectiveWith(GoodPolicySettings()));
        Assert.Empty(parsed.Refusals);
        var job = Assert.Single(parsed.Jobs);
        Assert.Equal("dev1", job.DeviceId);
        Assert.Equal("alice", job.OwnerUserId);
        Assert.Equal(2, job.Selection.Count);
        Assert.Equal(7, job.RetentionDays);
        Assert.Equal(24, job.Schedule.IntervalHours);
        var target = Assert.Single(parsed.Targets);
        Assert.Equal(BackupTargetKinds.Nas, target.Kind);
    }

    [Fact]
    public void RMM06_PolicyContent_Malformed_RefusedByName_WellFormedSurvive()
    {
        var s = GoodPolicySettings();
        s["backup.jobs"] = "job1,badretention,badtarget,noselection";
        s["backup.job.badretention.device"] = "dev1";
        s["backup.job.badretention.owner"] = "alice";
        s["backup.job.badretention.kind"] = "file";
        s["backup.job.badretention.selection"] = @"C:\x";
        s["backup.job.badretention.target"] = "nas1";
        s["backup.job.badretention.interval_hours"] = "24";
        s["backup.job.badretention.retention_days"] = "0"; // below the immutability floor
        s["backup.job.badtarget.device"] = "dev1";
        s["backup.job.badtarget.owner"] = "alice";
        s["backup.job.badtarget.kind"] = "file";
        s["backup.job.badtarget.selection"] = @"C:\x";
        s["backup.job.badtarget.target"] = "nope";
        s["backup.job.badtarget.interval_hours"] = "24";
        s["backup.job.badtarget.retention_days"] = "7";
        s["backup.job.noselection.device"] = "dev1";
        s["backup.job.noselection.owner"] = "alice";
        s["backup.job.noselection.kind"] = "file";
        s["backup.job.noselection.selection"] = "";
        s["backup.job.noselection.target"] = "nas1";
        s["backup.job.noselection.interval_hours"] = "24";
        s["backup.job.noselection.retention_days"] = "7";
        var parsed = BackupPolicyContent.Parse(EffectiveWith(s));
        Assert.Single(parsed.Jobs); // job1 survives
        Assert.Equal(3, parsed.Refusals.Count);
        Assert.Contains(parsed.Refusals, r => r.Contains("badretention") && r.Contains("immutability floor"));
        Assert.Contains(parsed.Refusals, r => r.Contains("badtarget"));
        Assert.Contains(parsed.Refusals, r => r.Contains("noselection"));
    }

    [Fact]
    public void RMM06_Schedule_DueLogic()
    {
        var sched = new BackupSchedule(24);
        Assert.True(sched.IsDue(null, T0));
        Assert.False(sched.IsDue(T0, T0.AddHours(23)));
        Assert.True(sched.IsDue(T0, T0.AddHours(24)));
    }

    // ---- running backups ----------------------------------------------

    [Fact]
    public void RMM06_FileBackup_HappyPath_SealedLocked_Verified_Audited()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        Assert.Equal(2, outcome.Files);
        Assert.Equal(9, outcome.Bytes); // "alpha" + "beta"
        var snapshot = rig.Store.GetSnapshot(outcome.SnapshotId!);
        Assert.NotNull(snapshot);
        Assert.True(snapshot!.IsSealed);
        Assert.True(snapshot.IsLocked(T0));
        Assert.Equal(T0.AddDays(7), snapshot.RetentionExpiresUtc);
        Assert.NotNull(rig.Store.GetManifestVerified(snapshot.Id));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backup_completed");
    }

    [Fact]
    public void RMM06_BackupRun_IsAnRmm15Job_StepsCompleteInOrder()
    {
        var auth = NewAuth();
        var journal = NewJournal(auth);
        var rig = NewRig(journal);
        var outcome = rig.Engine.RunBackup(FileJob(), Env(auth, "job-payload", T0), T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        var job = journal.GetJob(outcome.JobId!);
        Assert.NotNull(job);
        Assert.Equal(JobKinds.Backup, job!.Kind);
        Assert.Equal(JobStates.Done, job.State);
        Assert.All(job.Steps, s => Assert.Equal(StepStates.Done, s.State));
    }

    [Fact]
    public void RMM06_BackupRun_WithJournal_ButNoEnvelope_Refuses()
    {
        var auth = NewAuth();
        var rig = NewRig(NewJournal(auth));
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("signed envelope", outcome.Outcome);
        Assert.Empty(rig.Store.Snapshots);
    }

    [Fact]
    public void RMM06_BackupRun_PolicyToggleOff_RefusesByName()
    {
        var rig = NewRig(policyGate: _ => false);
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("rmm.backup.enabled", outcome.Outcome);
        Assert.Empty(rig.Store.Snapshots);
    }

    [Fact]
    public void RMM06_LargeFile_ChunksAndRestoresIdentically()
    {
        var rig = NewRig();
        var big = new byte[BackupSnapshotStore.ChunkSizeBytes + 12345];
        new Random(42).NextBytes(big);
        rig.Capture.AddFileBytes(@"C:\data\a.txt", big);
        var outcome = rig.Engine.RunBackup(FileJob(selection: new[] { @"C:\data\a.txt" }), envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        var manifest = rig.Store.GetManifestVerified(outcome.SnapshotId!);
        var entry = Assert.Single(manifest!.Entries);
        Assert.Equal(2, entry.ChunkHashes.Count);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(outcome.SnapshotId!, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.True(restore.Ok, restore.Outcome);
        Assert.Equal(big, target.Files[entry.Path]);
    }

    [Fact]
    public void RMM06_DirectoryStorage_RoundTrip()
    {
        var root = Path.Combine(Path.GetTempPath(), "acp-rmm06-" + Guid.NewGuid().ToString("N"));
        try
        {
            var auth = NewAuth();
            var store = new BackupSnapshotStore("nas1", new DirectoryBackupStorage(root), new SignedCommandVerifier(auth.Ring));
            var capture = new FakeBackupCaptureSource().AddFile(@"C:\data\a.txt", "on-disk");
            var engine = new BackupEngine(store, capture, new ChainedAuditLog());
            var outcome = engine.RunBackup(FileJob(selection: new[] { @"C:\data\a.txt" }), envelope: null, T0);
            Assert.True(outcome.Ok, outcome.Outcome);
            var target = new DirectoryRestoreTarget(Path.Combine(root, "restore"));
            var restore = engine.RestoreFiles(outcome.SnapshotId!, null, target,
                new RestoreRequester("alice", "dev1", false), envelope: null, T0);
            Assert.True(restore.Ok, restore.Outcome);
            var restored = Directory.EnumerateFiles(Path.Combine(root, "restore"), "*", SearchOption.AllDirectories).Single();
            Assert.Equal("on-disk", File.ReadAllText(restored));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    // ---- image + bare-metal ----------------------------------------------

    [Fact]
    public void RMM06_ImageBackup_BrowseInsideImage_AndBareMetalPlan()
    {
        var auth = NewAuth();
        var raw = new InMemoryBackupStorage();
        var verifier = new SignedCommandVerifier(auth.Ring);
        var store = new BackupSnapshotStore("nas1", raw, verifier);
        var capture = new FakeBackupCaptureSource()
            .AddVolume(new VolumeDescriptor("C", 500_000_000, "NTFS", 0, true, true),
                (@"Users\alice\doc.txt", "inside the image"))
            .AddVolume(new VolumeDescriptor("D", 900_000_000, "NTFS", 1, false, false),
                (@"data\blob.bin", "second volume"));
        var engine = new BackupEngine(store, capture, new ChainedAuditLog(), journal: null, verifier);
        var job = new BackupJobDefinition("img1", "dev1", "alice", BackupKinds.Image,
            new[] { "C:", "D:" }, "nas1", new BackupSchedule(24), 30, true);
        var outcome = engine.RunBackup(job, envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);

        // Browse inside the image without restoring:
        var (entries, refusal) = engine.BrowseSnapshot(outcome.SnapshotId!,
            new RestoreRequester("alice", "dev1", false), T0);
        Assert.Null(refusal);
        Assert.Equal(2, entries!.Count);
        Assert.Contains(entries, e => e.Path.StartsWith("vol-C/"));

        // Restore one file out of the image:
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = engine.RestoreFiles(outcome.SnapshotId!, new[] { "vol-C/Users/alice/doc.txt" }, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.True(restore.Ok, restore.Outcome);
        Assert.Equal("inside the image", Encoding.UTF8.GetString(target.Files["vol-C/Users/alice/doc.txt"]));

        // Bare-metal plan (admin + signed binding):
        var env = Env(auth, $"acp-backup-restore-v1|{outcome.SnapshotId}|dev1", T0);
        var (plan, planRefusal) = engine.BuildBareMetalPlan(outcome.SnapshotId!,
            new RestoreRequester("admin", "dev1", true), env, T0);
        Assert.Null(planRefusal);
        Assert.NotNull(plan);
        Assert.Equal(2, plan!.Volumes.Count);
        Assert.Contains(plan.Steps, s => s.Contains("partition 0"));
        Assert.Equal(outcome.SnapshotId, plan.Media.SnapshotId);
        Assert.Equal(plan.PlanHash, plan.Media.PlanHash);
    }

    [Fact]
    public void RMM06_BareMetal_OnFileSnapshot_OrByNonAdmin_Refuses()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var env = Env(rig.Auth, $"acp-backup-restore-v1|{outcome.SnapshotId}|dev1", T0);
        var (_, refusal1) = rig.Engine.BuildBareMetalPlan(outcome.SnapshotId!,
            new RestoreRequester("admin", "dev1", true), env, T0);
        Assert.Contains("file backup", refusal1!);
        var (_, refusal2) = rig.Engine.BuildBareMetalPlan(outcome.SnapshotId!,
            new RestoreRequester("alice", "dev1", false), env, T0);
        Assert.Contains("admin act", refusal2!);
    }

    // ---- restore flows -----------------------------------------------------

    [Fact]
    public void RMM06_SelfRestore_OwnFiles_OwnDevice_Works_AndAudits()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(outcome.SnapshotId!, new[] { "C/data/a.txt" }, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.True(restore.Ok, restore.Outcome);
        Assert.Equal(1, restore.FilesRestored);
        Assert.Equal("alpha", Encoding.UTF8.GetString(target.Files["C/data/a.txt"]));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "self_restore_completed");
    }

    [Fact]
    public void RMM06_Restore_UnknownPath_Refuses_NothingWritten()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(outcome.SnapshotId!, new[] { "C/data/nope.txt" }, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("not in snapshot", restore.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void RMM06_AdminRestore_SignedBinding_Works_WrongBindingRefuses()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var target = new InMemoryRestoreTarget(@"D:\restore");
        var good = Env(rig.Auth, $"acp-backup-restore-v1|{outcome.SnapshotId}|dev1", T0);
        var ok = rig.Engine.RestoreFiles(outcome.SnapshotId!, null, target,
            new RestoreRequester("admin", "dev1", true), good, T0);
        Assert.True(ok.Ok, ok.Outcome);
        var wrong = Env(rig.Auth, "acp-backup-restore-v1|some-other-snapshot|dev1", T0);
        var refused = rig.Engine.RestoreFiles(outcome.SnapshotId!, null, target,
            new RestoreRequester("admin", "dev1", true), wrong, T0);
        Assert.False(refused.Ok);
        Assert.Contains("does not bind", refused.Outcome);
    }

    // ---- retention / purge ---------------------------------------------------

    private static string SealOne(BackupSnapshotStore store, DateTimeOffset at, int retentionDays = 7)
    {
        var job = FileJob();
        var id = store.BeginSnapshot(job, at);
        store.AddFile(id, "C/data/a.txt", Encoding.UTF8.GetBytes("alpha"));
        return store.SealSnapshot(id, retentionDays, at).Id;
    }

    [Fact]
    public void RMM06_Purge_BeforeExpiry_Refused_AfterSteppedExpiry_Purges_BytesGone_RecordKept()
    {
        var rig = NewRig();
        var id = SealOne(rig.Store, T0);
        var early = rig.Engine.PurgeExpired(id, "admin", T0.AddDays(3));
        Assert.False(early.Purged);
        Assert.Contains("retention lock", early.Reason);
        // Step the clock forward in <48h hops (normal operation):
        rig.Store.ObserveTime(T0.AddDays(2));
        rig.Store.ObserveTime(T0.AddDays(4));
        rig.Store.ObserveTime(T0.AddDays(6));
        // AMENDED by the D38 F4 fix (disclosed): unattested advance
        // of the high-water mark is now anchored to real elapsed
        // time, so back-to-back ≤48h hops no longer ratchet trusted
        // time a week forward in-process — that pattern WAS the F4
        // attack. Crossing to day 7 takes the designed path: a
        // hub-signed time attestation.
        var attestation = Env(rig.Auth, $"acp-backup-time-v1|target=nas1|{T0.AddDays(7).AddHours(1):O}", T0.AddDays(7).AddHours(1));
        var done = rig.Engine.PurgeExpired(id, "admin", T0.AddDays(7).AddHours(1), attestation);
        Assert.True(done.Purged, done.Reason);
        var record = rig.Store.GetSnapshot(id);
        Assert.NotNull(record); // the record of its existence is never deleted
        Assert.Equal(SnapshotStates.Purged, record!.State);
        Assert.Null(rig.Raw.Get($"manifests/{id}.json"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "snapshot_purged");
    }

    [Fact]
    public void RMM06_Purge_RechainsCatalogue_ImportStillVerifies_SurvivorRestores()
    {
        var rig = NewRig();
        var first = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var second = rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1));
        Assert.True(first.Ok && second.Ok);
        // Expire + purge the FIRST record (the second must re-chain):
        for (var d = 1; d <= 7; d++) rig.Store.ObserveTime(T0.AddDays(d));
        // AMENDED by the D38 F4 fix (disclosed): the purge crosses
        // the retention boundary on a hub-signed time attestation —
        // unattested ≤48h hops no longer ratchet trusted time.
        var attestation = Env(rig.Auth, $"acp-backup-time-v1|target=nas1|{T0.AddDays(7).AddHours(1):O}", T0.AddDays(7).AddHours(1));
        var purge = rig.Engine.PurgeExpired(first.SnapshotId!, "admin", T0.AddDays(7).AddHours(1), attestation);
        Assert.True(purge.Purged, purge.Reason);
        var json = rig.Store.ExportCatalogue();
        var store2 = new BackupSnapshotStore("nas1", rig.Raw);
        var (ok, summary) = store2.ImportCatalogue(json);
        Assert.True(ok, summary);
        Assert.Equal(SnapshotStates.Purged, store2.GetSnapshot(first.SnapshotId!)!.State);
        Assert.True(store2.GetSnapshot(second.SnapshotId!)!.IsSealed);
    }

    [Fact]
    public void RMM06_Catalogue_Persistence_RoundTrip_ChainIntact()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var json = rig.Store.ExportCatalogue();
        var store2 = new BackupSnapshotStore("nas1", rig.Raw);
        var (ok, summary) = store2.ImportCatalogue(json);
        Assert.True(ok, summary);
        var snapshot = store2.GetSnapshot(outcome.SnapshotId!);
        Assert.NotNull(snapshot);
        Assert.True(snapshot!.IsSealed);
        Assert.NotNull(store2.GetManifestVerified(snapshot.Id));
    }

    // ---- usage + health -------------------------------------------------------

    [Fact]
    public void RMM06_Usage_Truthful_DedupAware()
    {
        var rig = NewRig();
        rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1)); // identical content: chunks dedup
        var usage = rig.Engine.Usage(T0.AddHours(1));
        Assert.Equal(2, usage.SealedSnapshots);
        Assert.Equal(2, usage.LockedSnapshots);
        Assert.Equal(18, usage.LogicalBytes);   // 9 bytes × 2 snapshots
        Assert.Equal(9, usage.StoredBytes);     // stored once
        Assert.Equal(18, usage.LockedBytes);
    }

    [Fact]
    public void RMM06_HealthFacts_NeverRun_Failed_Stale_Healthy()
    {
        var rig = NewRig();
        // Never run:
        var facts = rig.Engine.GetFacts("dev1", T0);
        var findings = BackupHealthEvaluator.Evaluate(facts, TimeSpan.FromHours(48), T0);
        Assert.Contains(findings, f => f.Kind == BackupConditionKinds.BackupNeverRun);
        // Failed run (empty fake selection content for one path is a
        // note, not a failure — use a throwing capture instead):
        var throwing = new FakeBackupCaptureSource().ThenThrow(new IOException("disk gone"));
        var engine2 = new BackupEngine(rig.Store, throwing, rig.Audit);
        engine2.RunBackup(FileJob(), envelope: null, T0);
        var failFindings = BackupHealthEvaluator.Evaluate(engine2.GetFacts("dev1", T0), TimeSpan.FromHours(48), T0);
        Assert.Contains(failFindings, f => f.Kind == BackupConditionKinds.BackupFailed);
        // Healthy after a real run:
        rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        var healthy = BackupHealthEvaluator.Evaluate(rig.Engine.GetFacts("dev1", T0.AddHours(1)), TimeSpan.FromHours(48), T0.AddHours(1));
        Assert.Empty(healthy);
        // Stale: same facts evaluated 10 days later against a 48h bound:
        var stale = BackupHealthEvaluator.Evaluate(rig.Engine.GetFacts("dev1", T0.AddDays(10)), TimeSpan.FromHours(48), T0.AddDays(10));
        Assert.Contains(stale, f => f.Kind == BackupConditionKinds.BackupStale);
    }

    [Fact]
    public void RMM06_DueJobs_NeverRunDue_JustRanNotDue()
    {
        var rig = NewRig();
        var job = FileJob();
        Assert.Single(rig.Engine.DueJobs(new[] { job }, "dev1", T0));
        rig.Engine.RunBackup(job, envelope: null, T0);
        Assert.Empty(rig.Engine.DueJobs(new[] { job }, "dev1", T0.AddHours(2)));
        Assert.Single(rig.Engine.DueJobs(new[] { job }, "dev1", T0.AddHours(25)));
    }

    // ---- Core service -----------------------------------------------------------

    [Fact]
    public void RMM06_Service_PolicyDriven_RunDueJobs_AndToggleOff()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var settings = GoodPolicySettings();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", settings, 1)).Allowed);
        IDeviceFacts Facts(string id) => StaticDeviceFacts.Of(id, "scope1");
        var raw = new InMemoryBackupStorage();
        var store = new BackupSnapshotStore("nas1", raw);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha").AddFile(@"C:\data\b.txt", "beta");
        var engine = new BackupEngine(store, capture, audit);
        var auth = NewAuth();
        var gate = new SignedCommandGate(new SignedCommandVerifier(auth.Ring), audit);
        var service = new BackupService(audit, policy, id => Facts(id), engine, gate, () => T0);

        var outcomes = service.RunDueJobs("dev1", envelope: null);
        Assert.Single(outcomes);
        Assert.True(outcomes[0].Ok, outcomes[0].Outcome);
        Assert.Single(service.PolicyFor("dev1").Jobs);
        Assert.Equal(1, service.Usage().SealedSnapshots);
        Assert.True(service.HealthFacts("dev1").LastSuccessUtc is not null);

        // Toggle OFF at device level: runs refuse by name.
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "dev-off", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { ["rmm.backup.enabled"] = "false" }, 1)).Allowed);
        var refused = service.RunDueJobs("dev1", envelope: null);
        Assert.False(refused[0].Ok);
        Assert.Contains("rmm.backup.enabled", refused[0].Outcome);
    }

    [Fact]
    public void RMM06_Service_SignedRunCommand_RunsNamedJob_UnsignedRefuses()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "dev-policy", PolicyLevels.Device, "dev1", GoodPolicySettings(), 1)).Allowed);
        var raw = new InMemoryBackupStorage();
        var store = new BackupSnapshotStore("nas1", raw);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha").AddFile(@"C:\data\b.txt", "beta");
        var engine = new BackupEngine(store, capture, audit);
        var auth = NewAuth();
        var gate = new SignedCommandGate(new SignedCommandVerifier(auth.Ring), audit);
        var service = new BackupService(audit, policy,
            id => StaticDeviceFacts.Of(id, "scope1"), engine, gate, () => T0);

        var unsigned = service.RunBackupCommand(envelope: null);
        Assert.False(unsigned.Ok);
        var signed = service.RunBackupCommand(Env(auth, "acp-backup-run-v1|job1", T0));
        Assert.True(signed.Ok, signed.Outcome);
        Assert.Equal(1, service.Usage().SealedSnapshots);
    }
}
