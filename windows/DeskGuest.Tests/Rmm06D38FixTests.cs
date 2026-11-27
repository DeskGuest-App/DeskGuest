using System.Text;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-06 D38 FIX — regression tests for the cross-review findings
// F1–F12 (packet 56d93b95). Every test here is the permanent
// regression for the finding named in it; the pre-existing suites
// (Rmm06Tests / Rmm06DestructionTests) are untouched except the
// three disclosed F4 amendments recorded in the lane log.
public class Rmm06D38FixTests
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

    private static SignedCommandEnvelope Env(Auth a, string payload, DateTimeOffset at) =>
        a.Signer.Sign(SignedCommandClasses.Automation, Encoding.UTF8.GetBytes(payload), at, TimeSpan.FromHours(2));

    private static BackupJobDefinition FileJob(string id = "job1", string device = "dev1", string owner = "alice",
        string target = "nas1", int intervalHours = 24, params string[] selection) => new(
            id, device, owner, BackupKinds.File,
            selection.Length > 0 ? selection : new[] { @"C:\data\a.txt", @"C:\data\b.txt" },
            target, new BackupSchedule(intervalHours), 7, true);

    private sealed record Rig(BackupSnapshotStore Store, InMemoryBackupStorage Raw, FakeBackupCaptureSource Capture,
        ChainedAuditLog Audit, BackupEngine Engine, Auth Auth, SignedCommandVerifier Verifier);

    private static Rig NewRig(Func<RestoreRequester, bool>? authenticator = null)
    {
        var auth = NewAuth();
        var raw = new InMemoryBackupStorage();
        var verifier = new SignedCommandVerifier(auth.Ring);
        var store = new BackupSnapshotStore("nas1", raw, verifier);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha")
            .AddFile(@"C:\data\b.txt", "beta");
        var audit = new ChainedAuditLog();
        var engine = new BackupEngine(store, capture, audit, journal: null, verifier,
            policyGate: null, requesterAuthenticator: authenticator);
        return new Rig(store, raw, capture, audit, engine, auth, verifier);
    }

    private static string SealDefault(Rig rig, BackupJobDefinition? job = null)
    {
        var outcome = rig.Engine.RunBackup(job ?? FileJob(), envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        return outcome.SnapshotId!;
    }

    private static SignedCommandEnvelope Attestation(Rig rig, DateTimeOffset at) =>
        Env(rig.Auth, $"deskguest-backup-time-v1|target=nas1|{at:O}", at);

    // ---- F1: high-water mark covered by catalogue integrity ---------

    [Fact]
    public void D38F1_HighWaterEditAlone_ImportsTampered_PurgeRefuses_MarkUnmoved()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var json = rig.Store.ExportCatalogue();
        // The F1 attack, verbatim: edit ONLY the HighWaterUtc field
        // of the saved catalogue — no chain recompute at all.
        var forged = System.Text.RegularExpressions.Regex.Replace(json,
            "\"HighWaterUtc\":\"[^\"]+\"", "\"HighWaterUtc\":\"2026-12-21T12:00:00+00:00\"");
        Assert.NotEqual(json, forged);
        var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
        var (ok, summary) = store2.ImportCatalogue(forged);
        Assert.False(ok);
        Assert.Contains("integrity", summary);
        Assert.True(store2.CatalogueTampered);
        // The forged mark never entered live state:
        Assert.Equal(DateTimeOffset.MinValue, store2.HighWaterUtc);
        // And the purge the forgery was setting up refuses:
        var engine2 = new BackupEngine(store2, rig.Capture, rig.Audit, journal: null, rig.Verifier);
        var purge = engine2.PurgeExpired(id, "attacker", T0.AddDays(30));
        Assert.False(purge.Purged);
        Assert.Contains("TAMPERED", purge.Reason);
    }

    [Fact]
    public void D38F1_HonestExport_ImportsClean_MarkPreserved()
    {
        var rig = NewRig();
        SealDefault(rig);
        var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
        var (ok, summary) = store2.ImportCatalogue(rig.Store.ExportCatalogue());
        Assert.True(ok, summary);
        Assert.Equal(rig.Store.HighWaterUtc, store2.HighWaterUtc);
    }

    // ---- F2: tail-drop / whole-file deletion -------------------------

    [Fact]
    public void D38F2_TailRecordDropped_ImportsTampered()
    {
        var rig = NewRig();
        SealDefault(rig);
        rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1));
        Assert.Equal(2, rig.Store.Snapshots.Count);
        var json = rig.Store.ExportCatalogue();
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        var snapshots = root.GetProperty("Snapshots").EnumerateArray().ToList();
        // Drop the NEWEST record; keep the original integrity field.
        // The forward chain over the remaining record still verifies
        // — only the document integrity (count + head) catches this.
        var dropped = "{\"TargetId\":\"nas1\",\"HighWaterUtc\":\"" + root.GetProperty("HighWaterUtc").GetString() +
                      "\",\"Snapshots\":[" + snapshots[0].GetRawText() +
                      "],\"Integrity\":\"" + root.GetProperty("Integrity").GetString() + "\"}";
        var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
        var (ok, _) = store2.ImportCatalogue(dropped);
        Assert.False(ok);
        Assert.True(store2.CatalogueTampered);
    }

    [Fact]
    public void D38F2_CatalogueFileDeleted_AnchorSurvives_LoadRefuses_NotEmpty()
    {
        var rig = NewRig();
        SealDefault(rig);
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-rmm06-f2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "catalogue.json");
            rig.Store.SaveCatalogueToFile(path);
            // Honest load works while the file exists:
            var honest = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
            var (okHonest, honestSummary) = honest.LoadCatalogueFromFile(path);
            Assert.True(okHonest, honestSummary);
            Assert.Single(honest.Snapshots);
            // Delete the catalogue file outright — the anchor remains:
            File.Delete(path);
            var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
            var (ok, summary) = store2.LoadCatalogueFromFile(path);
            Assert.False(ok);
            Assert.Contains("MISSING", summary);
            Assert.True(store2.CatalogueTampered);
            // A path with neither file nor anchor is a legit empty:
            var fresh = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
            var (okFresh, _) = fresh.LoadCatalogueFromFile(Path.Combine(dir, "never-existed.json"));
            Assert.True(okFresh);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void D38F2_CatalogueFileReplaced_OlderCopy_AnchorDisagrees_LoadRefuses()
    {
        var rig = NewRig();
        SealDefault(rig);
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-rmm06-f2b-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "catalogue.json");
            rig.Store.SaveCatalogueToFile(path);
            var olderJson = File.ReadAllText(path);
            rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1));
            rig.Store.SaveCatalogueToFile(path); // anchor now covers 2 records
            File.WriteAllText(path, olderJson);  // attacker rolls the file back to 1 record
            var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
            var (ok, summary) = store2.LoadCatalogueFromFile(path);
            Assert.False(ok);
            Assert.Contains("anchor", summary);
            Assert.True(store2.CatalogueTampered);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // ---- F3: chunk GC fails closed -----------------------------------

    [Fact]
    public void D38F3_GarbageCollection_FailsClosed_WhenSealedManifestUnverifiable()
    {
        var rig = NewRig();
        var first = SealDefault(rig);
        var second = SealDefault(rig);
        // Poison the SECOND snapshot's manifest blob so it no longer
        // verifies — it drops out of the provably-referenced set:
        rig.Raw.Put($"manifests/{second}.json", Encoding.UTF8.GetBytes("{\"not\":\"a manifest\"}"));
        Assert.Null(rig.Store.GetManifestVerified(second));
        // Stage a third snapshot with a UNIQUE chunk and abort it:
        // its chunk is a GC candidate, but GC must delete NOTHING
        // while a sealed manifest is unverifiable.
        var staged = rig.Store.BeginSnapshot(FileJob(), T0);
        var entry = rig.Store.AddFile(staged, "C/data/unique.txt", Encoding.UTF8.GetBytes("unique-bytes"));
        var uniqueChunk = entry.ChunkHashes.Single();
        rig.Store.AbortSnapshot(staged);
        Assert.True(rig.Raw.Exists($"chunks/{uniqueChunk}")); // survived: GC failed closed
        // The healthy survivor's chunks are untouched too:
        var manifest = rig.Store.GetManifestVerified(first);
        Assert.NotNull(manifest);
        Assert.All(manifest!.Entries.SelectMany(e => e.ChunkHashes),
            c => Assert.True(rig.Raw.Exists($"chunks/{c}")));
    }

    // ---- F4: clock ratchet bound --------------------------------------

    [Fact]
    public void D38F4_TightLoopRatchet_CannotAdvanceMark_PurgeStillRefused()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // The F4 attack: +47h per public call, ~16 calls, in a tight
        // in-process loop — previously enough to defeat a 30-day
        // lock in seconds. (7-day lock here; same shape.)
        var t = T0;
        for (var i = 0; i < 16; i++) { t = t.AddHours(47); rig.Store.ObserveTime(t); }
        Assert.True(rig.Store.HighWaterUtc <= T0.AddHours(48),
            $"mark ratcheted to {rig.Store.HighWaterUtc:O}");
        var purge = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30));
        Assert.False(purge.Purged);
        Assert.Contains("clock jumped", purge.Reason);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
    }

    [Fact]
    public void D38F4_RefusedDelete_DoesNotAdvanceMark()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var del = rig.Store.TryDeleteSnapshot(id, "attacker", T0.AddHours(47));
        Assert.False(del.Deleted);
        Assert.Equal(T0, rig.Store.HighWaterUtc);
    }

    [Fact]
    public void D38F4_AttestedJump_StillPurges_AfterRatchetAttempt()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var t = T0;
        for (var i = 0; i < 4; i++) { t = t.AddHours(47); rig.Store.ObserveTime(t); }
        var purge = rig.Engine.PurgeExpired(id, "hub-operator", T0.AddDays(30), Attestation(rig, T0.AddDays(30)));
        Assert.True(purge.Purged, purge.Reason);
    }

    // ---- F5: vendor-cloud locator spellings ----------------------------

    [Fact]
    public void D38F5_VendorCloudSpellings_RefusedForEveryKind()
    {
        // (a) kind=local with a UNC locator naming Azure Files:
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Local, @"\\acct.file.core.windows.net\share").Validate());
        // (b) a port on smb:// (Azure Files is SMB on 445):
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, "smb://acct.file.core.windows.net:445/share").Validate());
        // (c) a trailing-dot FQDN:
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, @"\\x.blob.core.windows.net.\share").Validate());
        // (d) WebDAV UNC @SSL:
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.SiteServer, @"\\bucket.s3.amazonaws.com@SSL\share").Validate());
        // Legitimate spellings still admitted — a port on the user's
        // own filer is not a cloud:
        Assert.Null(new BackupStorageTarget("t", BackupTargetKinds.Nas, "smb://filer01:445/share").Validate());
        Assert.Null(new BackupStorageTarget("t", BackupTargetKinds.Local, @"\\filer01\backups").Validate());
    }

    // ---- F6: system-path guard ------------------------------------------

    [Fact]
    public void D38F6_SystemPath_SpellingsDetected_LegitPathsAdmitted()
    {
        Assert.True(BackupEngine.IsSystemPath(@"\\?\C:\Windows\System32"));
        Assert.True(BackupEngine.IsSystemPath(@"\\localhost\C$\Windows"));
        Assert.True(BackupEngine.IsSystemPath(@"C:\PROGRA~1"));
        Assert.True(BackupEngine.IsSystemPath(@"D:\Windows"));            // Windows not on C:
        Assert.True(BackupEngine.IsSystemPath(@"C:\"));                   // bare drive root
        Assert.True(BackupEngine.IsSystemPath(@"E:\Program Files (x86)\app"));
        Assert.False(BackupEngine.IsSystemPath(@"C:\Users\alice\Restore"));
        Assert.False(BackupEngine.IsSystemPath(@"D:\restore"));
    }

    [Fact]
    public void D38F6_DevicePrefixSystemRoot_RestoreRefused()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"\\?\C:\Windows");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("system path", restore.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void D38F6_SelfRestore_CannotAllowSystemPaths_AdminSignedCan()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Windows\System32\drivers");
        // A self-restore caller setting the flag changes nothing:
        var self = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0, allowSystemPaths: true);
        Assert.False(self.Ok);
        Assert.Contains("system path", self.Outcome);
        Assert.Empty(target.Files);
        // The flag is honoured only behind a verified admin envelope.
        // DS-P9-F16 (Wave 12): exercising it into a system path now
        // requires the v2 payload, which BINDS the destination and
        // the permission — the v1 payload signed neither, so a v1
        // envelope replayed at a different destination no longer
        // carries system-path rights.
        var env = Env(rig.Auth, $"deskguest-backup-restore-v2|{id}|dev1|{target.RootPath}|true|*", T0);
        var admin = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("admin", "dev1", true), env, T0, allowSystemPaths: true);
        Assert.True(admin.Ok, admin.Outcome);
        Assert.Equal(2, admin.FilesRestored);
    }

    // ---- F7: requester authentication seam --------------------------------

    [Fact]
    public void D38F7_UnauthenticatedRequester_Refused_WhenAuthenticatorWired()
    {
        // The host session belongs to bob; a caller CLAIMING to be
        // alice (the snapshot owner) is not alice's session:
        var rig = NewRig(authenticator: r => r.UserId == "bob" && r.DeviceId == "dev1");
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var forged = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(forged.Ok);
        Assert.Contains("could not be authenticated", forged.Outcome);
        Assert.Empty(target.Files);
        var (_, browseRefusal) = rig.Engine.BrowseSnapshot(id, new RestoreRequester("alice", "dev1", false), T0);
        Assert.NotNull(browseRefusal);
        // The authenticated session restores its own snapshot:
        var bobRig = NewRig(authenticator: r => r.UserId == "bob" && r.DeviceId == "dev1");
        var bobJob = FileJob(owner: "bob");
        var bobId = SealDefault(bobRig, bobJob);
        var okTarget = new InMemoryRestoreTarget(@"C:\Users\bob\Restore");
        var ok = bobRig.Engine.RestoreFiles(bobId, null, okTarget,
            new RestoreRequester("bob", "dev1", false), envelope: null, T0);
        Assert.True(ok.Ok, ok.Outcome);
    }

    // ---- F8: restore rollback ----------------------------------------------

    private sealed class ThrowingWriteTarget : IRestoreTarget
    {
        private readonly InMemoryRestoreTarget _inner;
        private readonly string _failPath;
        public ThrowingWriteTarget(string root, string failPath) { _inner = new InMemoryRestoreTarget(root); _failPath = failPath; }
        public string RootPath => _inner.RootPath;
        public IReadOnlyDictionary<string, byte[]> Files => _inner.Files;
        public void Seed(string path, string content) => _inner.Write(path, Encoding.UTF8.GetBytes(content));
        public void Write(string relativePath, byte[] content)
        {
            if (relativePath == _failPath) throw new IOException("disk full mid-restore");
            _inner.Write(relativePath, content);
        }
        public void Delete(string relativePath) => _inner.Delete(relativePath);
        public bool Exists(string relativePath) => _inner.Exists(relativePath);
        public byte[]? Read(string relativePath) => _inner.Read(relativePath);
    }

    [Fact]
    public void D38F8_WriteFailureMidRestore_OriginalsRestored_NothingPartialStands()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var manifest = rig.Store.GetManifestVerified(id)!;
        var firstPath = manifest.Entries[0].Path;
        var secondPath = manifest.Entries[1].Path;
        var target = new ThrowingWriteTarget(@"C:\Users\alice\Restore", secondPath);
        target.Seed(firstPath, "USER-ORIGINAL"); // a pre-existing file the restore would overwrite
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("rollback", restore.Outcome);
        // The user's original is BACK — not deleted by rollback:
        Assert.Equal("USER-ORIGINAL", Encoding.UTF8.GetString(target.Files[firstPath]));
        Assert.False(target.Files.ContainsKey(secondPath));
    }

    [Fact]
    public void D38F8_VerificationFailure_WritesNothing_OriginalUntouched()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var manifest = rig.Store.GetManifestVerified(id)!;
        var firstPath = manifest.Entries[0].Path;
        var secondChunk = manifest.Entries[1].ChunkHashes[0];
        rig.Raw.Put($"chunks/{secondChunk}", Encoding.UTF8.GetBytes("beta-but-evil"));
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        target.Write(firstPath, Encoding.UTF8.GetBytes("USER-ORIGINAL"));
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        // Two-phase restore: verification happens before ANY write,
        // so the original was never touched in the first place.
        Assert.Equal("USER-ORIGINAL", Encoding.UTF8.GetString(target.Files[firstPath]));
        Assert.Single(target.Files);
    }

    // ---- F9: capture gaps + manifest read-back -------------------------------

    [Fact]
    public void D38F9_PartialCapture_MissingSelectionItem_FailsRun_NothingSealed()
    {
        var rig = NewRig();
        var job = FileJob(selection: new[] { @"C:\data\a.txt", @"C:\data\missing.txt" });
        var outcome = rig.Engine.RunBackup(job, envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("capture_incomplete", outcome.Outcome);
        Assert.Contains("missing.txt", outcome.Outcome);
        Assert.Empty(rig.Store.Snapshots);
        var facts = rig.Engine.GetFacts("dev1", T0);
        Assert.NotEqual("completed", facts.LastOutcome);
    }

    private sealed class ManifestCorruptingStorage : IBackupStorage
    {
        private readonly IBackupStorage _inner;
        public ManifestCorruptingStorage(IBackupStorage inner) => _inner = inner;
        public long? FreeBytes => _inner.FreeBytes;
        public void Put(string key, byte[] bytes) => _inner.Put(key, bytes);
        public byte[]? Get(string key)
        {
            var b = _inner.Get(key);
            if (b is not null && key.StartsWith("manifests/") && b.Length > 0) { b = b.ToArray(); b[0] ^= 0xFF; }
            return b;
        }
        public bool Exists(string key) => _inner.Exists(key);
        public IReadOnlyList<string> ListKeys(string prefix) => _inner.ListKeys(prefix);
        public void Delete(string key) => _inner.Delete(key);
    }

    [Fact]
    public void D38F9_ManifestReadBackMismatch_SealRefused_NothingCatalogued()
    {
        var auth = NewAuth();
        var store = new BackupSnapshotStore("nas1", new ManifestCorruptingStorage(new InMemoryBackupStorage()),
            new SignedCommandVerifier(auth.Ring));
        var capture = new FakeBackupCaptureSource().AddFile(@"C:\data\a.txt", "alpha");
        var engine = new BackupEngine(store, capture, new ChainedAuditLog());
        var outcome = engine.RunBackup(FileJob(selection: new[] { @"C:\data\a.txt" }), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("seal_failed", outcome.Outcome);
        Assert.Empty(store.Snapshots);
    }

    // ---- F10: per-job run state ------------------------------------------------

    [Fact]
    public void D38F10_SiblingJobs_DoNotResetEachOthers_DueNessOrFailures()
    {
        var rig = NewRig();
        var hourly = FileJob(id: "hourly", intervalHours: 1);
        var dailyFailing = FileJob(id: "daily", intervalHours: 24,
            selection: new[] { @"C:\data\a.txt", @"C:\data\missing.txt" });
        // The daily job FAILS at T0; the hourly job SUCCEEDS after it:
        var fail = rig.Engine.RunBackup(dailyFailing, envelope: null, T0);
        Assert.False(fail.Ok);
        var ok = rig.Engine.RunBackup(hourly, envelope: null, T0.AddMinutes(30));
        Assert.True(ok.Ok, ok.Outcome);
        // Due-ness at T0+2h: the hourly job is due again on its own
        // clock; the daily job is NOT — the hourly run must not have
        // reset the daily job's last attempt.
        var due = rig.Engine.DueJobs(new[] { hourly, dailyFailing }, "dev1", T0.AddHours(2));
        Assert.Contains(due, j => j.Id == "hourly");
        Assert.DoesNotContain(due, j => j.Id == "daily");
        // The sibling's success did not reset the failure count:
        var deviceFacts = rig.Engine.GetFacts("dev1", T0.AddHours(2));
        Assert.Equal(1, deviceFacts.ConsecutiveFailures);
        // Per-job facts name the failing job, and the evaluator
        // raises backup_failed from them (per-job condition shape):
        var jobFacts = rig.Engine.GetFacts("dev1", "daily", T0.AddHours(2));
        Assert.Equal(1, jobFacts.ConsecutiveFailures);
        Assert.NotEqual("completed", jobFacts.LastOutcome);
        var findings = BackupHealthEvaluator.Evaluate(jobFacts, TimeSpan.FromHours(48), T0.AddHours(2));
        Assert.Contains(findings, f => f.Kind == BackupConditionKinds.BackupFailed);
    }

    // ---- F11: gate consistency ---------------------------------------------------

    [Fact]
    public void D38F11_RunBackup_JobForAnotherTarget_Refused_NothingWritten()
    {
        var rig = NewRig();
        var outcome = rig.Engine.RunBackup(FileJob(target: "other-target"), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("job_target_mismatch", outcome.Outcome);
        Assert.Empty(rig.Store.Snapshots);
    }

    [Fact]
    public void D38F11_Import_ForAnotherTarget_Refused()
    {
        var rig = NewRig();
        SealDefault(rig);
        var other = new BackupSnapshotStore("other-target", rig.Raw, rig.Verifier);
        var (ok, summary) = other.ImportCatalogue(rig.Store.ExportCatalogue());
        Assert.False(ok);
        Assert.Contains("NOT trusted", summary);
        Assert.True(other.CatalogueTampered);
    }

    [Fact]
    public void D38F11_BrowseAndBareMetal_EnforceTamperGate_LikeRestore()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // Break the catalogue: import garbage into the live store.
        var (ok, _) = rig.Store.ImportCatalogue("{ not json");
        Assert.False(ok);
        Assert.True(rig.Store.CatalogueTampered);
        var (_, browseRefusal) = rig.Engine.BrowseSnapshot(id, new RestoreRequester("alice", "dev1", false), T0);
        Assert.NotNull(browseRefusal);
        Assert.Contains("catalogue_tampered", browseRefusal);
        var env = Env(rig.Auth, $"deskguest-backup-restore-v1|{id}|dev1", T0);
        var (_, planRefusal) = rig.Engine.BuildBareMetalPlan(id, new RestoreRequester("admin", "dev1", true), env, T0);
        Assert.NotNull(planRefusal);
        Assert.Contains("catalogue_tampered", planRefusal);
    }

    // ---- F12: robustness -------------------------------------------------------------

    [Fact]
    public void D38F12_DuplicateRequestPaths_RefusedByName_NoThrow()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(id,
            new[] { "C/data/a.txt", "c/DATA/A.txt" }, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("duplicate", restore.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void D38F12_AttestationTime_WithoutOffset_Refused()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // A signed attestation whose time carries no offset is
        // ambiguous — it must not move trusted time.
        var attestation = Env(rig.Auth, "deskguest-backup-time-v1|target=nas1|2026-12-21T12:00:00", T0.AddDays(30));
        var purge = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30), attestation);
        Assert.False(purge.Purged);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
    }
}
