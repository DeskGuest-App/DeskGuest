using System.Text;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-06 DESTRUCTION PASS — attacks on endpoint backup.
// Attacker models: (a) ransomware running as the endpoint user /
// agent — it can call every public API the agent exposes and write
// to the raw storage target; (b) a compromised hub issuing
// perfectly signed commands; (c) a malicious or confused end user
// attempting self-restore escapes; (d) poisoned storage/catalogue
// bytes. The attacker does NOT hold the customer's signing key
// beyond what model (b) grants, and never the attestation key for
// a target it does not name.
public class Rmm06DestructionTests
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

    private static BackupJobDefinition FileJob(params string[] selection) => new(
        "job1", "dev1", "alice", BackupKinds.File,
        selection.Length > 0 ? selection : new[] { @"C:\data\a.txt", @"C:\data\b.txt" },
        "nas1", new BackupSchedule(24), 7, true);

    private sealed record Rig(BackupSnapshotStore Store, InMemoryBackupStorage Raw, FakeBackupCaptureSource Capture,
        ChainedAuditLog Audit, BackupEngine Engine, Auth Auth, SignedCommandVerifier Verifier);

    private static Rig NewRig()
    {
        var auth = NewAuth();
        var raw = new InMemoryBackupStorage();
        var verifier = new SignedCommandVerifier(auth.Ring);
        var store = new BackupSnapshotStore("nas1", raw, verifier);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha")
            .AddFile(@"C:\data\b.txt", "beta");
        var audit = new ChainedAuditLog();
        var engine = new BackupEngine(store, capture, audit, journal: null, verifier);
        return new Rig(store, raw, capture, audit, engine, auth, verifier);
    }

    private static string SealDefault(Rig rig)
    {
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        return outcome.SnapshotId!;
    }

    private static void StepClock(BackupSnapshotStore store, DateTimeOffset from, DateTimeOffset to)
    {
        // Advance observed time in <48h hops — the shape of a device
        // that keeps running and reporting while time passes.
        var t = from;
        while (t < to) { t = t.AddHours(24); if (t > to) t = to; store.ObserveTime(t); }
    }

    // ---- immutability: deletion through every door -------------------

    [Fact]
    public void ATTACK_DeleteSealedSnapshot_AgentItself_Refused_SnapshotIntact()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var outcome = rig.Store.TryDeleteSnapshot(id, "endpoint-agent", T0.AddDays(1));
        Assert.False(outcome.Deleted);
        Assert.Contains("immutable", outcome.Reason);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
        Assert.NotNull(rig.Store.GetManifestVerified(id));
    }

    [Fact]
    public void ATTACK_DeleteSealedSnapshot_UnderSignedHubCommand_Refused_AndAudited()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // The hub command is genuine and signed — immutability does
        // not care. (The engine's delete surface never even verifies
        // a signature: there is no signature that authorises this.)
        var outcome = rig.Engine.RequestDelete(id, "hub-operator", underSignedCommand: true, T0.AddDays(1));
        Assert.False(outcome.Deleted);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "snapshot_delete_refused");
        // Even AFTER retention expiry, a delete (not purge) refuses:
        StepClock(rig.Store, T0, T0.AddDays(8));
        var late = rig.Engine.RequestDelete(id, "hub-operator", underSignedCommand: true, T0.AddDays(8));
        Assert.False(late.Deleted);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
    }

    [Fact]
    public void ATTACK_OverwriteSealedChunk_RestoreRefuses_NothingPoisonedWritten()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var manifest = rig.Store.GetManifestVerified(id)!;
        var chunk = manifest.Entries[0].ChunkHashes[0];
        // Ransomware with raw storage write access corrupts the chunk:
        rig.Raw.Put($"chunks/{chunk}", Encoding.UTF8.GetBytes("pwned"));
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        // W10 / V2-C2: the refusal is pinned BY NAME — the chunk
        // layer's own named refusal, not any failure containing
        // the word "chunk".
        Assert.StartsWith("chunk verification failed for", restore.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void ATTACK_SwapManifestBlob_RestoreRefuses_ManifestHashMismatch()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // Attacker replaces the stored manifest with one pointing at
        // attacker content — the catalogue's chained hash disagrees:
        var forged = new BackupManifest(id, "job1", "dev1", "alice", BackupKinds.File,
            new[] { new BackupManifestEntry("evil.txt", 4, BackupHashing.Sha256Hex("evil"), new[] { rig.Store.WriteChunk(Encoding.UTF8.GetBytes("evil")) }) },
            Array.Empty<VolumeDescriptor>());
        rig.Raw.Put($"manifests/{id}.json", Encoding.UTF8.GetBytes(forged.CanonicalJson()));
        Assert.Null(rig.Store.GetManifestVerified(id));
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("manifest failed verification against the catalogue", restore.Outcome);
        Assert.Empty(target.Files);
    }

    // ---- retention games: the clock -----------------------------------

    [Fact]
    public void ATTACK_ClockJumpForward_PurgeRefused_WithoutAttestation()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // Attacker rolls the endpoint clock 30 days forward in one
        // jump and purges: the store's high-water mark exposes it.
        var outcome = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30));
        Assert.False(outcome.Purged);
        Assert.Contains("clock jumped", outcome.Reason);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
    }

    [Fact]
    public void ATTACK_ClockJump_WithAttestationForWrongTarget_Refused()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var attestation = Env(rig.Auth, $"deskguest-backup-time-v1|target=other-target|{T0.AddDays(30):O}", T0.AddDays(30));
        var outcome = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30), attestation);
        Assert.False(outcome.Purged);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
    }

    [Fact]
    public void DEFENCE_ClockJump_WithValidAttestation_Purges()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // The hub (trusted time source) attests the jumped-to time:
        var attestation = Env(rig.Auth, $"deskguest-backup-time-v1|target=nas1|{T0.AddDays(30):O}", T0.AddDays(30));
        var outcome = rig.Engine.PurgeExpired(id, "hub-operator", T0.AddDays(30), attestation);
        Assert.True(outcome.Purged, outcome.Reason);
        Assert.Equal(SnapshotStates.Purged, rig.Store.GetSnapshot(id)!.State);
    }

    [Fact]
    public void ATTACK_RefusedOperations_DoNotLaunderClockJumps()
    {
        // Found by the destruction pass: store paths that advanced
        // the clock high-water from an UNVALIDATED presented time
        // let a refused operation (a delete attempt, a failed
        // attestation) launder a one-shot clock roll into trusted
        // time, after which a purge at the same time looked
        // un-jumped. Fixed: jumped readings freeze the effective
        // time; only a verified attestation crosses a jump.
        var rig = NewRig();
        var id = SealDefault(rig);
        // 1) A delete attempt presented at a rolled-forward time:
        var del = rig.Engine.RequestDelete(id, "attacker", underSignedCommand: false, T0.AddDays(30));
        Assert.False(del.Deleted);
        // 2) A purge with a FAILED attestation (wrong target):
        var badAttestation = Env(rig.Auth, $"deskguest-backup-time-v1|target=other-target|{T0.AddDays(30):O}", T0.AddDays(30));
        var p1 = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30), badAttestation);
        Assert.False(p1.Purged);
        // 3) The purge the laundering was setting up — same rolled
        // time, no attestation — must STILL read as a clock jump:
        var p2 = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(30));
        Assert.False(p2.Purged);
        Assert.Contains("clock jumped", p2.Reason);
        Assert.True(rig.Store.GetSnapshot(id)!.IsSealed);
        Assert.Equal(T0, rig.Store.HighWaterUtc); // the mark never moved
    }

    [Fact]
    public void ATTACK_SealWithZeroRetention_StoreItselfRefuses()
    {
        // Policy parsing is not the only gate: the store refuses a
        // sub-floor retention even when called directly.
        var rig = NewRig();
        var staged = rig.Store.BeginSnapshot(FileJob(), T0);
        rig.Store.AddFile(staged, "C/data/a.txt", Encoding.UTF8.GetBytes("alpha"));
        Assert.Throws<ArgumentException>(() => rig.Store.SealSnapshot(staged, 0, T0));
        Assert.Empty(rig.Store.Snapshots);
    }

    [Fact]
    public void ATTACK_ClockRollback_NeverUnlocksEarly()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        // Time legitimately passes to day 6 (lock still on), then the
        // attacker rolls BACK and tries purge games at odd times:
        StepClock(rig.Store, T0, T0.AddDays(6));
        var outcome = rig.Engine.PurgeExpired(id, "attacker", T0.AddDays(1));
        Assert.False(outcome.Purged);
        Assert.Contains("retention lock", outcome.Reason);
    }

    // ---- catalogue tampering -------------------------------------------

    [Fact]
    public void ATTACK_CatalogueRetentionEdit_ImportsTampered_PurgeAndRestoreRefuse()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var json = rig.Store.ExportCatalogue();
        // Attacker shortens the retention in the persisted catalogue:
        var tampered = System.Text.RegularExpressions.Regex.Replace(json,
            "\"RetentionExpiresUtc\":\"[^\"]+\"", "\"RetentionExpiresUtc\":\"2026-11-20T12:00:00+00:00\"");
        Assert.NotEqual(json, tampered);
        var store2 = new BackupSnapshotStore("nas1", rig.Raw, rig.Verifier);
        var (ok, summary) = store2.ImportCatalogue(tampered);
        Assert.False(ok);
        Assert.Contains("BROKEN", summary);
        var engine2 = new BackupEngine(store2, rig.Capture, rig.Audit, journal: null, rig.Verifier);
        var purge = engine2.PurgeExpired(id, "attacker", T0.AddDays(1));
        Assert.False(purge.Purged);
        Assert.Contains("TAMPERED", purge.Reason);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = engine2.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0.AddDays(1));
        Assert.False(restore.Ok);
        Assert.Contains("catalogue_tampered", restore.Outcome);
        // And the tamper is a first-class health finding:
        var findings = BackupHealthEvaluator.Evaluate(engine2.GetFacts("dev1", T0.AddDays(1)), TimeSpan.FromDays(2), T0.AddDays(1));
        Assert.Contains(findings, f => f.Kind == BackupConditionKinds.BackupCatalogueTampered && f.Severity == "critical");
    }

    [Fact]
    public void ATTACK_CatalogueRecordDropped_ChainBreaks_Tampered()
    {
        var rig = NewRig();
        SealDefault(rig);
        rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1));
        Assert.Equal(2, rig.Store.Snapshots.Count);
        var json = rig.Store.ExportCatalogue();
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var snapshots = doc.RootElement.GetProperty("Snapshots").EnumerateArray().ToList();
        var dropped = "{\"TargetId\":\"nas1\",\"HighWaterUtc\":\"" + doc.RootElement.GetProperty("HighWaterUtc").GetString() +
                      "\",\"Snapshots\":[" + snapshots[1].GetRawText() + "]}";
        var store2 = new BackupSnapshotStore("nas1", rig.Raw);
        var (ok, _) = store2.ImportCatalogue(dropped);
        Assert.False(ok); // first record's PrevCatalogueHash no longer links to GENESIS
        Assert.True(store2.CatalogueTampered);
    }

    // ---- restore-scope escapes -------------------------------------------

    [Fact]
    public void ATTACK_SelfRestore_CrossUser_RefusedAndAudited()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Users\mallory\Restore");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("mallory", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("belongs to user 'alice'", restore.Outcome);
        Assert.Empty(target.Files);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "self_restore_refused");
    }

    [Fact]
    public void ATTACK_SelfRestore_CrossDevice_Refused_BrowseAlsoScoped()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev2", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("own device", restore.Outcome);
        var (_, browseRefusal) = rig.Engine.BrowseSnapshot(id,
            new RestoreRequester("alice", "dev2", false), T0);
        Assert.NotNull(browseRefusal);
    }

    [Fact]
    public void ATTACK_RestoreOverSystemPath_RefusedByDefault()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"C:\Windows\System32\drivers");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("system path", restore.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void ATTACK_ManifestPathTraversal_RefusedAtEveryLayer()
    {
        // The validator itself:
        Assert.NotNull(BackupSnapshotStore.ValidateManifestPath("../evil.txt"));
        Assert.NotNull(BackupSnapshotStore.ValidateManifestPath("a/../../evil.txt"));
        Assert.NotNull(BackupSnapshotStore.ValidateManifestPath("/abs.txt"));
        Assert.NotNull(BackupSnapshotStore.ValidateManifestPath(@"C:\evil.txt"));
        Assert.Null(BackupSnapshotStore.ValidateManifestPath("C/data/a.txt"));
        // The store refuses to even stage a traversal path:
        var rig = NewRig();
        var staged = rig.Store.BeginSnapshot(FileJob(), T0);
        Assert.Throws<ArgumentException>(() => rig.Store.AddFile(staged, "../evil.txt", Encoding.UTF8.GetBytes("x")));
    }

    // ---- backup poisoning ---------------------------------------------------

    [Fact]
    public void ATTACK_ManifestLiesAboutContents_RestoreRefuses_AndRollsBack()
    {
        // A manifest whose FileHash does not match its chunks can
        // only exist if storage AND catalogue were both written by
        // the attacker — model the end state directly at the store
        // layer: stage a file, then corrupt the staged manifest's
        // entry hash before seal via a second staged snapshot is not
        // possible through the API, so attack the CHUNK bytes under
        // a sealed snapshot and confirm per-file rollback: file A
        // restores, file B's chunk is corrupt, A is rolled back.
        var rig = NewRig();
        var id = SealDefault(rig);
        var manifest = rig.Store.GetManifestVerified(id)!;
        var secondChunk = manifest.Entries[1].ChunkHashes[0];
        rig.Raw.Put($"chunks/{secondChunk}", Encoding.UTF8.GetBytes("beta-but-evil")); // wrong bytes, wrong hash
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Empty(target.Files); // the good file was rolled back too — no partial restore stands
    }

    [Fact]
    public void ATTACK_PurgeSharedChunks_SurvivingSnapshotStillRestores()
    {
        var rig = NewRig();
        var first = SealDefault(rig);
        var secondOutcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0.AddHours(1));
        Assert.True(secondOutcome.Ok);
        var second = secondOutcome.SnapshotId!;
        // Expire ONLY the first snapshot: step time to day 7+1h
        // (second snapshot, sealed at T0+1h, expires T0+7d+1h — the
        // same instant; purge the first, the second's chunks must
        // survive because they are shared):
        StepClock(rig.Store, T0, T0.AddDays(7).AddHours(1));
        // AMENDED by the D38 F4 fix (disclosed): StepClock's
        // back-to-back hops no longer ratchet the high-water mark a
        // week forward (that was the F4 attack shape); the purge
        // crosses expiry on a hub-signed time attestation instead.
        var attestation = Env(rig.Auth, $"deskguest-backup-time-v1|target=nas1|{T0.AddDays(7).AddHours(1):O}", T0.AddDays(7).AddHours(1));
        var purge = rig.Engine.PurgeExpired(first, "admin", T0.AddDays(7).AddHours(1), attestation);
        Assert.True(purge.Purged, purge.Reason);
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore");
        var restore = rig.Engine.RestoreFiles(second, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0.AddDays(7).AddHours(1));
        Assert.True(restore.Ok, restore.Outcome);
        Assert.Equal(2, restore.FilesRestored);
    }

    // ---- storage-target smuggling --------------------------------------------

    [Fact]
    public void ATTACK_CloudEndpointDressedAsNas_RefusedByShape()
    {
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, @"\\nas.backblazeb2.com\share").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.SiteServer, "smb://storage.googleapis.com/share").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, @"\\bucket.s3.amazonaws.com\share").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Local, "https://dropbox.com/backups").Validate());
        Assert.NotNull(new BackupStorageTarget("t", BackupTargetKinds.Nas, "s3://my-bucket/backups").Validate());
    }

    // ---- success-while-writing-nothing -----------------------------------------

    [Fact]
    public void ATTACK_EmptyCapture_ReportsFailure_NotSuccess_NoSnapshot_JournalFailed()
    {
        var auth = NewAuth();
        var journal = new JobJournal(NewIdentity(), null);
        var raw = new InMemoryBackupStorage();
        var store = new BackupSnapshotStore("nas1", raw);
        var empty = new FakeBackupCaptureSource(); // selection paths absent: capture yields nothing
        var engine = new BackupEngine(store, empty, new ChainedAuditLog(), journal);
        var outcome = engine.RunBackup(FileJob(), Env(auth, "job-payload", T0), T0);
        Assert.False(outcome.Ok);
        Assert.Contains("empty_capture", outcome.Outcome);
        Assert.Empty(store.Snapshots);
        var job = journal.GetJob(outcome.JobId!);
        Assert.Equal(JobStates.Failed, job!.State);
        var facts = engine.GetFacts("dev1", T0);
        Assert.NotEqual("completed", facts.LastOutcome);
    }

    [Fact]
    public void ATTACK_VerifySabotage_CorruptReadBack_RunFails_NothingSealed()
    {
        var raw = new CorruptingStorage(new InMemoryBackupStorage());
        var store = new BackupSnapshotStore("nas1", raw);
        var capture = new FakeBackupCaptureSource().AddFile(@"C:\data\a.txt", "alpha");
        var engine = new BackupEngine(store, capture, new ChainedAuditLog());
        var outcome = engine.RunBackup(FileJob(selection: new[] { @"C:\data\a.txt" }), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("verify_failed", outcome.Outcome);
        Assert.Empty(store.Snapshots);
    }

    /// <summary>Storage that flips a byte on every chunk read — the
    /// read-back verify exists precisely to catch this.</summary>
    private sealed class CorruptingStorage : IBackupStorage
    {
        private readonly IBackupStorage _inner;
        public CorruptingStorage(IBackupStorage inner) => _inner = inner;
        public long? FreeBytes => _inner.FreeBytes;
        public void Put(string key, byte[] bytes) => _inner.Put(key, bytes);
        public byte[]? Get(string key)
        {
            var b = _inner.Get(key);
            if (b is not null && key.StartsWith("chunks/") && b.Length > 0) { b = b.ToArray(); b[0] ^= 0xFF; }
            return b;
        }
        public bool Exists(string key) => _inner.Exists(key);
        public IReadOnlyList<string> ListKeys(string prefix) => _inner.ListKeys(prefix);
        public void Delete(string key) => _inner.Delete(key);
    }

    // ---- authority escapes -------------------------------------------------------

    [Fact]
    public void ATTACK_AdminRestore_UnsignedOrReplayedForOtherSnapshot_Refused()
    {
        var rig = NewRig();
        var id = SealDefault(rig);
        var target = new InMemoryRestoreTarget(@"D:\restore");
        var unsigned = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("admin", "dev1", true), envelope: null, T0);
        Assert.False(unsigned.Ok);
        // Envelope minted for a bare-metal plan on ANOTHER snapshot:
        var other = Env(rig.Auth, "deskguest-backup-restore-v1|deadbeef|dev1", T0);
        var cross = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("admin", "dev1", true), other, T0);
        Assert.False(cross.Ok);
        Assert.Contains("does not bind", cross.Outcome);
        Assert.Empty(target.Files);
    }

    [Fact]
    public void ATTACK_PolicyKillSwitch_MidRun_AbortsBeforeSeal()
    {
        var calls = 0;
        Func<string, bool> gate = _ => { calls++; return calls == 1; }; // ON at start, OFF before seal
        var raw = new InMemoryBackupStorage();
        var store = new BackupSnapshotStore("nas1", raw);
        var capture = new FakeBackupCaptureSource().AddFile(@"C:\data\a.txt", "alpha");
        var engine = new BackupEngine(store, capture, new ChainedAuditLog(), journal: null, commandVerifier: null, gate);
        var outcome = engine.RunBackup(FileJob(selection: new[] { @"C:\data\a.txt" }), envelope: null, T0);
        Assert.False(outcome.Ok);
        Assert.Contains("policy_disabled_mid_run", outcome.Outcome);
        Assert.Empty(store.Snapshots); // staged snapshot was aborted, nothing sealed
    }
}
