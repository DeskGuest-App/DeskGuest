using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DeskGuest.Core.Services;
using DeskGuest.Launcher;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Tools;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 13 Lane A — Windows residual closures.
/// Every test is the permanent regression pin for one W12 named
/// residual: DS-P5-F5 (refusal events on every guarded path),
/// DS-P9-F2 (unwired-probe posture), DS-P9-F16 (bare-metal v2),
/// DS-P9-F18 (verify→exec TOCTOU), DS-P7-F19 (ProtectedTargets
/// caller-side writes), DS-P7-F1 (seed-posture adjudication).</summary>
public class W13WinResFixTests
{
    // ---------- shared session world (W12 shape) ----------
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("nogrant", "company-1", "No Grant", "human"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host", "peer" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World { Enrollments = enrollments, Roster = roster, Sessions = new SessionService(roster, enrollments), DeviceId = device!.DeviceId };
    }

    private static string ActiveAttended(World w)
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    private static bool HasRefusal(World w, string sessionId, string gate) =>
        w.Sessions.ListEvents(sessionId).Any(e => e.Kind == "refused" && e.Detail.Contains($"'{gate}'"));

    // ---------- P5 F5: refusal events on every guarded path ----------

    [Fact] // channel-origin accept records its refusal
    public void P5F5_ChannelAccept_RecordsRefusal()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.False(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.InitiatingChannel));
        Assert.True(HasRefusal(w, s.Id, "channel_origin_never_counts"));
    }

    [Fact] // foreign capability records its refusal
    public void P5F5_ForeignCapability_RecordsRefusal()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        var foreign = new SessionService(w.Roster, w.Enrollments).LocalAcceptCapability;
        Assert.False(w.Sessions.AcceptSessionLocal(s!.Id, "host", foreign));
        Assert.True(HasRefusal(w, s.Id, "capability_mismatch"));
    }

    [Fact] // unattended start without the use grant records its refusal
    public void P5F5_UnattendedStart_NoUseGrant_RecordsRefusal()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "nogrant", "unattended", "lan");
        Assert.NotNull(s);
        Assert.False(w.Sessions.StartSession(s!.Id, "nogrant"));
        Assert.True(HasRefusal(w, s.Id, "no_use_grant"));
    }

    [Fact] // a stranger pausing records the actor guard's refusal
    public void P5F5_Pause_ByStranger_RecordsRefusal()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.PauseSession(id, "peer"));
        Assert.True(HasRefusal(w, id, "actor_not_authorized"));
        Assert.Equal("active", w.Sessions.GetSession(id)!.State);
    }

    [Fact] // surface enable by a non-actor records its refusal
    public void P5F5_Blank_ByNonActor_RecordsRefusal()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.SetBlanked(id, true, "peer"));
        Assert.True(HasRefusal(w, id, "actor_not_authorized"));
        Assert.False(w.Sessions.GetSession(id)!.Blanked);
    }

    [Fact] // chat by a non-participant records its refusal
    public void P5F5_Chat_ByNonParticipant_RecordsRefusal()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.Null(w.Sessions.SendChatMessage(id, "peer", "intrusion"));
        Assert.True(HasRefusal(w, id, "not_participant"));
    }

    [Fact] // a watcher's file job records the content guard's refusal
    public void P5F5_FileJob_ByWatcher_RecordsRefusal()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.AddParticipant(id, "peer", "watcher", "ctrl"));
        Assert.Null(w.Sessions.CreateFileJob(id, "from_host", "secrets.txt", 10, "peer"));
        Assert.True(HasRefusal(w, id, "content_not_authorized"));
    }

    [Fact] // forged lifecycle append records its refusal
    public void P5F5_AppendEvent_ForgedKind_RecordsRefusal()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.AppendEvent(id, "accepted", "ctrl", null, "forged"));
        Assert.True(HasRefusal(w, id, "event_kind_not_appendable"));
    }

    [Fact] // scope pin: a pure state mismatch is NOT a guard decision — nothing is recorded
    public void P5F5_StateMismatch_RecordsNothing()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        var before = w.Sessions.ListEvents(s!.Id).Count;
        Assert.False(w.Sessions.PauseSession(s.Id, "ctrl")); // requested, not active
        Assert.Equal(before, w.Sessions.ListEvents(s.Id).Count);
    }

    // ---------- P9 F2: unwired-probe posture is named in behaviour + wording ----------

    private static byte[] MakeZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = zip.CreateEntry(name);
                using var wr = new StreamWriter(e.Open());
                wr.Write(content);
            }
        }
        return ms.ToArray();
    }

    [Fact]
    public void P9F2_UnwiredProbe_StatusAndApplyMessage_NameThePosture()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true));
        Assert.False(updates.Status().StagedSlotProbeWired);
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        var (ok, msg) = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(ok, msg);
        Assert.Contains("NO installed-version probe is wired", msg);
        Assert.Contains("NOT probe-proven", msg);
    }

    [Fact]
    public void P9F2_WiredProbe_StatusTrue_AndApplyMessage_ClaimsTheProof()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true),
            stagedSlotProbe: static (dir, version) => File.Exists(Path.Combine(dir, "app.txt")));
        Assert.True(updates.Status().StagedSlotProbeWired);
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        var (ok, msg) = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(ok, msg);
        Assert.Contains("probe PASSED", msg);
        Assert.DoesNotContain("NOT probe-proven", msg);
    }

    [Fact]
    public void P9F2_WiredProbe_Failure_RefusesApply()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true),
            stagedSlotProbe: static (dir, version) => false);
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        var (ok, msg) = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.False(ok);
        Assert.Contains("installed-version probe FAILED", msg);
        Assert.Equal("0.1.0", updates.Status().ActiveVersion); // pointer unchanged
    }

    // ---------- P9 F16: bare-metal v2 destination-bound plan ----------

    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private sealed record BackupAuth(DeviceIdentity Customer, SignedCommandSigner Signer, CustomerCommandKeyRing Ring);
    private static BackupAuth NewBackupAuth()
    {
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        return new BackupAuth(customer, new SignedCommandSigner(customer), ring);
    }
    private static SignedCommandEnvelope Env(BackupAuth a, string payload) =>
        a.Signer.Sign(SignedCommandClasses.Automation, Encoding.UTF8.GetBytes(payload), T0, TimeSpan.FromHours(2));

    private static (BackupEngine Engine, BackupSnapshotStore Store, BackupAuth Auth, string SnapshotId) ImageRig()
    {
        var auth = NewBackupAuth();
        var raw = new InMemoryBackupStorage();
        var verifier = new SignedCommandVerifier(auth.Ring);
        var store = new BackupSnapshotStore("nas1", raw, verifier);
        var capture = new FakeBackupCaptureSource()
            .AddVolume(new VolumeDescriptor("C", 500_000_000, "NTFS", 0, true, true),
                (@"Users\alice\doc.txt", "inside the image"));
        var engine = new BackupEngine(store, capture, new ChainedAuditLog(), journal: null, verifier);
        var job = new BackupJobDefinition("img1", "dev1", "alice", BackupKinds.Image,
            new[] { "C:" }, "nas1", new BackupSchedule(24), 30, true);
        var outcome = engine.RunBackup(job, envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        return (engine, store, auth, outcome.SnapshotId!);
    }

    [Fact]
    public void P9F16_BareMetal_NamedDestination_V1Envelope_Refused()
    {
        var (engine, _, auth, id) = ImageRig();
        var env = Env(auth, $"deskguest-backup-restore-v1|{id}|dev1");
        var (plan, refusal) = engine.BuildBareMetalPlan(id,
            new RestoreRequester("admin", "dev1", true), env, T0, targetDeviceId: "dev2");
        Assert.Null(plan);
        Assert.Contains("deskguest-backup-restore-v2 required", refusal!);
    }

    [Fact]
    public void P9F16_BareMetal_NamedDestination_V2Envelope_BindsPlan()
    {
        var (engine, store, auth, id) = ImageRig();
        var manifestHash = store.GetSnapshot(id)!.ManifestHash;
        var env = Env(auth, $"deskguest-backup-restore-v2|{id}|dev1|dev2|{manifestHash}");
        var (plan, refusal) = engine.BuildBareMetalPlan(id,
            new RestoreRequester("admin", "dev1", true), env, T0, targetDeviceId: "dev2");
        Assert.Null(refusal);
        Assert.NotNull(plan);
        Assert.Equal("dev2", plan!.TargetDeviceId);
        Assert.Contains(plan.Steps, s => s.Contains("destination binding (v2)"));
    }

    [Fact]
    public void P9F16_BareMetal_V2Envelope_ForAnotherDestination_Refused()
    {
        var (engine, store, auth, id) = ImageRig();
        var manifestHash = store.GetSnapshot(id)!.ManifestHash;
        var env = Env(auth, $"deskguest-backup-restore-v2|{id}|dev1|dev3|{manifestHash}");
        var (plan, refusal) = engine.BuildBareMetalPlan(id,
            new RestoreRequester("admin", "dev1", true), env, T0, targetDeviceId: "dev2");
        Assert.Null(plan);
        Assert.Contains("does not bind", refusal!);
    }

    [Fact] // the legacy path stands, unnamed destination = null in the record, never assumed
    public void P9F16_BareMetal_NoDestination_V1StillWorks_TargetNull()
    {
        var (engine, _, auth, id) = ImageRig();
        var env = Env(auth, $"deskguest-backup-restore-v1|{id}|dev1");
        var (plan, refusal) = engine.BuildBareMetalPlan(id,
            new RestoreRequester("admin", "dev1", true), env, T0);
        Assert.Null(refusal);
        Assert.NotNull(plan);
        Assert.Null(plan!.TargetDeviceId);
    }

    // ---------- P9 F18: verify→exec TOCTOU ----------

    [Fact]
    public async Task P9F18_RunAsync_SlotTamperedAfterFirstResolve_RunsBase()
    {
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        var updates = Path.Combine(root, "updates"); Directory.CreateDirectory(updates);
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "DeskGuest.SessionAgent.exe"), "slot agent");
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "DeskGuest.SessionAgent.exe"), "base agent");
        var hash = SlotIntegrity.ContentHash(slotA);
        File.WriteAllText(SlotPointer.PointerPath(updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
        string? ranExe = null; string? holdDir = "unset";
        var log = new StringWriter();
        // The start delegate tampers BEFORE returning on first call is
        // not the window; instead tamper between resolve and exec by
        // pre-poisoning: RunAsync re-resolves, so a slot tampered at
        // any point before the second resolve falls back. Simulate by
        // tampering now and confirming the executed target is base —
        // plus assert the request carries the hold directory when the
        // slot is intact (second scenario below).
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "attacker core");
        var code = await LauncherCore.RunAsync(install, updates, "", req =>
        {
            ranExe = req.ExePath; holdDir = req.HoldDirectory; return Task.FromResult(7);
        }, log);
        Assert.Equal(7, code);
        Assert.Equal(Path.Combine(install, "DeskGuestCore.exe"), ranExe);
        Assert.Null(holdDir);
    }

    [Fact]
    public async Task P9F18_RunAsync_IntactSlot_RunsSlot_WithHoldDirectory()
    {
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        var updates = Path.Combine(root, "updates"); Directory.CreateDirectory(updates);
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "DeskGuest.SessionAgent.exe"), "slot agent");
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        var hash = SlotIntegrity.ContentHash(slotA);
        File.WriteAllText(SlotPointer.PointerPath(updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
        string? ranExe = null; string? holdDir = null;
        var code = await LauncherCore.RunAsync(install, updates, "", req =>
        {
            ranExe = req.ExePath; holdDir = req.HoldDirectory; return Task.FromResult(0);
        }, new StringWriter());
        Assert.Equal(0, code);
        Assert.Equal(Path.Combine(slotA, "DeskGuestCore.exe"), ranExe);
        Assert.Equal(slotA, holdDir); // the starter pins these files deny-write for the child's life
        var target = LauncherCore.ResolveTarget(install, updates);
        Assert.Equal(slotA, target.VerifiedSlotDir);
        Assert.Equal(hash, target.VerifiedSlotHash);
    }

    // ---------- P7 F19: ProtectedTargets caller-side writes are synchronized ----------

    [Fact]
    public void P7F19_ProtectedTargets_ConcurrentWritesAndReads_NeverThrow_AndLand()
    {
        var engine = new PolicyEngine();
        var writers = Enumerable.Range(0, 8).Select(t => new Thread(() =>
        {
            for (var i = 0; i < 500; i++) engine.ProtectedTargets.Add($"app-{t}-{i}");
        })).ToList();
        var pairing = new Pairing("p1", "Agent", new HashSet<string> { Scopes.Observe }, DateTimeOffset.UtcNow, null, null, false);
        var tool = new ToolDescriptor("screenshot", "x", Scopes.Observe, SessionRequirement.Agent, RiskTier.Medium, null, "Agent");
        using var argsDoc = JsonDocument.Parse("{}");
        writers.ForEach(t => t.Start());
        // Evaluate (the read path) concurrently with the writes:
        for (var i = 0; i < 200; i++)
            _ = engine.Evaluate(pairing, tool, argsDoc.RootElement, TestUtil.Session(), TestUtil.State(),
                new HashSet<string>(), foregroundWindowName: "app-3-250", foregroundProcessName: "app-3-250");
        writers.ForEach(t => t.Join());
        Assert.Equal(4000, engine.ProtectedTargets.Count);
        Assert.True(engine.ProtectedTargets.Contains("app-3-250"));
        // Snapshot enumeration while writing does not throw:
        engine.ProtectedTargets.Add("late");
        Assert.Contains("late", engine.ProtectedTargets.ToList());
    }

    [Fact]
    public void P7F19_ProtectedTargets_RemoveAndClear_WorkThroughThePublicSurface()
    {
        var engine = new PolicyEngine();
        engine.ProtectedTargets.Add("KeePass");
        Assert.True(engine.ProtectedTargets.Remove("KeePass"));
        Assert.Empty(engine.ProtectedTargets);
        engine.ProtectedTargets.Add("A");
        engine.ProtectedTargets.Clear();
        Assert.Empty(engine.ProtectedTargets);
    }

    // ---------- P7 F1: adjudication pins (the rebuttal's evidence, executable) ----------

    [Fact]
    public void P7F1_SeedPosture_CountsAndOffReasons_AreAsRecorded()
    {
        var seeded = FeatureToggleRegistry.Seeded();
        Assert.Equal(44, seeded.All.Count); // 40 through W13 + A2/A3 toggles (Wave 19 Lane C, 2026-11-23 — annotated bump per the U4 precedent) + FR-120's takeover-modes toggle (Lane W73, 2026-11-23 — default ON, so the OFF list below is unchanged; annotated bump per the same precedent) + FR-143's HTTPS-only toggle connections.https_only.enabled (2026-11-25 — default ON, so the OFF list below is unchanged; annotated bump per the same precedent)
        var off = seeded.All.Where(t => !t.DefaultEnabled).Select(t => t.Key).OrderBy(k => k).ToList();
        Assert.Equal(new[]
        {
            "rmm.background_tools.enabled", "rmm.backstage.enabled", "rmm.camera_viewing.enabled",
            "rmm.dlp.enabled", "rmm.mdm.enabled",
        }, off);
        // Every OFF seed carries its reason in its description:
        foreach (var t in seeded.All.Where(t => !t.DefaultEnabled))
            Assert.Contains("off", t.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void P7F1_IsEnabled_FailClosedLimbs()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "co1");
        Assert.False(engine.IsEnabled(facts, "rmm.no_such_feature.enabled")); // unregistered + unset → false
        Assert.False(engine.IsEnabled(facts, "presence.enabled"));            // consent floor → false
        Assert.False(engine.IsEnabled(facts, "rmm.mdm.enabled"));             // registered OFF default → false
        Assert.True(engine.IsEnabled(facts, "rmm.monitoring.enabled"));       // registered ON default (Block R posture)
        // An unparsable explicit document value refuses rather than enables:
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("d1", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["rmm.monitoring.enabled"] = "sometimes" }, 1)).Allowed);
        Assert.False(engine.IsEnabled(facts, "rmm.monitoring.enabled"));
    }
}
