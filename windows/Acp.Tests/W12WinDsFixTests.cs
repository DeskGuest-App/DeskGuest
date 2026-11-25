using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Acp.Core.Modules;
using Acp.Core.Services;
using Acp.Shared.Enrollment;
using Acp.Shared.Input;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Policy;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 12 Lane A — round-1 dispositions (packets
/// P5, P6, P9 + the Windows half of P7). Every test here is the
/// permanent regression pin for one dispositioned finding; the
/// finding id is in the test name.</summary>
public class W12WinDsFixTests
{
    // ---------- shared session world (SessionTests shape) ----------
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

    // ---------- P5 ----------

    [Fact] // DS-P5-F2: revocation ends the device's live sessions
    public void P5F2_EndSessionsForDevice_EndsLiveSession()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.Equal(1, w.Sessions.EndSessionsForDevice(w.DeviceId));
        Assert.Equal("ended", w.Sessions.GetSession(id)!.State);
        Assert.Equal(SessionService.EndReasonDeviceRevoked, w.Sessions.GetSession(id)!.EndReason);
        Assert.Equal(0, w.Sessions.EndSessionsForDevice(w.DeviceId)); // idempotent
    }

    [Fact] // DS-P5-F1: the capability accept refuses a foreign capability object
    public void P5F1_AcceptSessionLocal_RequiresTheServicesOwnCapability()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        var foreign = new SessionService(w.Roster, w.Enrollments).LocalAcceptCapability;
        Assert.False(w.Sessions.AcceptSessionLocal(s!.Id, "host", foreign));
        Assert.Null(w.Sessions.GetSession(s.Id)!.AcceptedByUserId);
        Assert.True(w.Sessions.AcceptSessionLocal(s.Id, "host", w.Sessions.LocalAcceptCapability));
    }

    [Fact] // DS-P5-F5: a refused accept is audit-logged as a refusal
    public void P5F5_RefusedAccept_RecordsRefusalEvent()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.False(w.Sessions.AcceptSession(s!.Id, "ghost", SessionAcceptOrigin.EndpointLocal));
        var refusal = w.Sessions.ListEvents(s.Id).SingleOrDefault(e => e.Kind == "refused");
        Assert.NotNull(refusal);
        Assert.Contains("acceptor_not_live_human", refusal!.Detail);
    }

    [Fact] // DS-P5-F8: blocking a session releases its input block
    public void P5F8_BlockSession_ClearsInputBlocked()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.SetInputBlocked(id, true, "host"));
        Assert.True(w.Sessions.GetSession(id)!.InputBlocked);
        Assert.True(w.Sessions.BlockSession(id, "ctrl"));
        Assert.False(w.Sessions.GetSession(id)!.InputBlocked);
    }

    [Fact] // DS-P5-F13: chat does not flow before consent (requested state)
    public void P5F13_Chat_InRequestedSession_Refused()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.Null(w.Sessions.SendChatMessage(s!.Id, "ctrl", "hello before consent"));
        var id = ActiveAttended(w);
        Assert.NotNull(w.Sessions.SendChatMessage(id, "ctrl", "hello after consent"));
    }

    [Fact] // DS-P5-F18: session end records the watermark clear
    public void P5F18_EndSession_RecordsWatermarkCleared()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.SetWatermarked(id, true, "host"));
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        Assert.Contains(w.Sessions.ListEvents(id), e => e.Kind == "watermark_cleared");
    }

    [Fact] // DS-P5-F19: resume is recorded as "resumed", not a second "started"
    public void P5F19_Resume_RecordsResumedEvent()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.PauseSession(id, "ctrl"));
        Assert.True(w.Sessions.ResumeSession(id, "ctrl"));
        var kinds = w.Sessions.ListEvents(id).Select(e => e.Kind).ToList();
        Assert.Contains("resumed", kinds);
        Assert.Equal(1, kinds.Count(k => k == "started"));
    }

    [Fact] // DS-P5-F20: STOP from "requested" ends directly — no illegal requested→blocked edge
    public void P5F20_StopFromRequested_EndsWithoutBlockedPassThrough()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StopSession(s.Id, "host"));
        Assert.Equal("ended", w.Sessions.GetSession(s.Id)!.State);
        Assert.DoesNotContain(w.Sessions.ListEvents(s.Id), e => e.Kind == "blocked");
    }

    [Fact] // DS-P5-F12: AppendEvent cannot forge lifecycle kinds; linkage kinds still work
    public void P5F12_AppendEvent_ForgedKindsRefused()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.AppendEvent(id, "accepted", "ctrl", null, "forged"));
        Assert.False(w.Sessions.AppendEvent(id, "ended", "ctrl", null, "forged"));
        Assert.False(w.Sessions.AppendEvent(id, "tunnel_opened", "outsider-x", null, "forged actor"));
        Assert.True(w.Sessions.AppendEvent(id, "tunnel_opened", "ctrl", "tun-1", "linked"));
    }

    [Fact] // DS-P5-F6: the floor holder who did NOT set the blank cannot clear the host's blank
    public void P5F6_FloorHolder_CannotClearHostsBlank_SetterAndHostCan()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host")); // ctrl drives
        Assert.True(w.Sessions.SetBlanked(id, true, "host"));   // host sets the blank
        Assert.False(w.Sessions.SetBlanked(id, false, "ctrl")); // the constrained driver cannot release it
        Assert.True(w.Sessions.GetSession(id)!.Blanked);
        Assert.True(w.Sessions.SetBlanked(id, false, "host"));  // host clears
    }

    // ---------- P6 ----------

    private sealed class FakeSink : IInputReleaseSink
    {
        public List<string> Ups = new();
        public void ReleaseKey(ushort vk) => Ups.Add($"key:{vk:X2}");
        public void ReleaseMouseButton(string b) => Ups.Add($"button:{b}");
    }

    [Fact] // DS-P6-F1: a ReleaseAll racing a press (inside sendDown) leaves nothing down+untracked
    public void P6F1_PressKey_ReleaseAllRacesInsideSendDown_PressRefusedAndUpSent()
    {
        var tracker = new HeldInputTracker();
        var sink = new FakeSink();
        var downSent = false; var upSent = false;
        var result = tracker.PressKey(0x11,
            sendDown: () => { downSent = true; tracker.ReleaseAll(sink); },
            sendUp: () => { upSent = true; });
        Assert.True(downSent);
        Assert.False(result);          // the press lost the race and says so
        Assert.True(upSent);           // the compensating up went out after the down
        Assert.False(tracker.HasHeldInput);
    }

    [Fact] // DS-P6-F9: replay never backfills events published before the pairing attached
    public void P6F9_ReplaySince_NoPreAttachBackfill()
    {
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, (_, _) => true, "dev-1");
        bus.Publish(AgentEventKinds.ForegroundApp, "before attach", null);
        store.Subscribe("p-new", new[] { AgentEventKinds.ForegroundApp });
        var handlerCalls = 0;
        bus.Attach("p-new", _ => handlerCalls++);
        Assert.Empty(bus.ReplaySince("p-new", 0));
        bus.Publish(AgentEventKinds.ForegroundApp, "after attach", null);
        var replay = bus.ReplaySince("p-new", 0);
        Assert.Single(replay);
        Assert.Equal("after attach", replay[0].Detail);
    }

    [Fact] // DS-P6-F4: no public scope-free ShouldDeliver overload remains
    public void P6F4_ShouldDeliver_ScopeFreeOverload_IsNotPublic()
    {
        var publics = typeof(AgentEventBus).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(m => m.Name == "ShouldDeliver").ToList();
        Assert.All(publics, m => Assert.True(m.GetParameters().Length >= 4,
            "a public ShouldDeliver must require a scope delegate"));
    }

    [Fact] // DS-P6-F15: the event-kind registry cannot be mutated through its IReadOnlySet face
    public void P6F15_EventKindRegistry_IsImmutable()
    {
        Assert.IsNotType<HashSet<string>>(AgentEventKinds.All);
    }

    [Fact] // DS-P6-F16: a null kind refuses the whole subscribe
    public void P6F16_Subscribe_NullKind_Refused()
    {
        var store = new EventSubscriptionStore();
        var (ok, err) = store.Subscribe("p1", new string[] { null! });
        Assert.False(ok);
        Assert.Contains("unknown_event_kind", err);
    }

    [Fact] // DS-P6-F6/F7/F19: Core SessionManager — atomic start, ownership stop, paused expiry
    public void P6F6F7F19_CoreSessionManager_Guards()
    {
        var mgr = new SessionManager();
        var p1 = new Pairing("p1", "Agent One", new HashSet<string> { Scopes.Observe }, DateTimeOffset.UtcNow, null, null, false);
        var p2 = new Pairing("p2", "Agent Two", new HashSet<string> { Scopes.Observe }, DateTimeOffset.UtcNow, null, null, false);
        Assert.NotNull(mgr.Start(p1));
        Assert.Null(mgr.Start(p2)); // F6: a second start cannot clobber the live session
        Assert.False(mgr.TryStopForPairing("p2", out var ended)); // F7
        Assert.Null(ended);
        Assert.NotNull(mgr.Current);
        Assert.True(mgr.Pause("tripwire"));
        Assert.Null(mgr.ExpiryReason(DateTimeOffset.UtcNow.AddHours(2))); // F19: paused ≠ idle-expired
        Assert.True(mgr.TryStopForPairing("p1", out ended));
        Assert.NotNull(ended);
    }

    // ---------- P9 ----------

    private static byte[] MakeZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = zip.CreateEntry(name);
                using var w = new StreamWriter(e.Open());
                w.Write(content);
            }
        }
        return ms.ToArray();
    }

    [Fact] // DS-P9-F5: an apply with no staged hash refuses (no fail-open flip)
    public void P9F5_Apply_WithoutStagedHash_Refuses()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true));
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        // Hand-edit the pointer: drop the staged hash (the pre-anchor shape).
        var pointerPath = Path.Combine(root, "active-slot.json");
        using (var doc = JsonDocument.Parse(File.ReadAllText(pointerPath)))
        {
            var rootEl = doc.RootElement;
            var dict = new Dictionary<string, object?>();
            foreach (var prop in rootEl.EnumerateObject())
                dict[prop.Name] = prop.Name == "StagedSlotHash" ? null : prop.Value.Clone();
            File.WriteAllText(pointerPath, JsonSerializer.Serialize(dict));
        }
        var (ok, msg) = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.False(ok);
        Assert.Contains("no content hash", msg);
    }

    [Fact] // DS-P9-F15: a refused package does not destroy the previous valid staging
    public void P9F15_RefusedPackage_KeepsPreviousStaging()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true));
        var good = MakeZip(("app.txt", "good"));
        Assert.True(updates.StagePackage(good, signer.Sign(good), "2.0.0").Ok);
        var evil = MakeZip(("../escape.txt", "x"));
        var (ok, _) = updates.StagePackage(evil, signer.Sign(evil), "9.9.9");
        Assert.False(ok);
        Assert.Equal("2.0.0", updates.Status().StagedVersion);
        var (applied, _) = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(applied);
    }

    [Fact] // DS-P9-F24: malformed base64 in the update tool is a tool error, not an exception
    public void P9F24_UpdateTool_MalformedBase64_ReturnsError()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true));
        var module = new AgentUpdateModule(updates);
        using var doc = JsonDocument.Parse("""{"action":"stage","package_base64":"!!!not-base64!!!","signature_base64":"%%%","version":"2.0.0"}""");
        var pairing = new Pairing("p1", "Agent", new HashSet<string> { Scopes.Admin }, DateTimeOffset.UtcNow, null, null, false);
        var ctx = new ToolExecutionContext(pairing, TestUtil.Session(), TestUtil.State(), new HashSet<string>(), TestUtil.TempDir());
        var result = module.ExecuteAsync(doc.RootElement, ctx, default).GetAwaiter().GetResult();
        Assert.False(result.Ok);
    }

    [Fact] // DS-P9-F8/F11: "{}" main pointer falls back to the last-known-good .bak, not slot A
    public void P9F8F11_SlotPointer_EmptyObject_FallsBackToBak()
    {
        var root = TestUtil.TempDir();
        File.WriteAllText(SlotPointer.PointerPath(root), "{}");
        File.WriteAllText(SlotPointer.PointerBackupPath(root),
            """{"Active":1,"Version":"2.3.4","StagedVersion":null,"LastOutcome":"flipped","ActiveSlotHash":"abc"}""");
        var read = SlotPointer.ReadDetailed(root);
        Assert.Equal(SlotId.B, read.Pointer.Active);
        Assert.Equal("2.3.4", read.Pointer.Version);
        Assert.NotNull(read.FellBack);
        Assert.Contains(".bak", read.FellBack);
    }

    [Fact] // DS-P9-F18: a reparse point inside a slot fails verification closed
    public void P9F18_SlotIntegrity_SymlinkInSlot_VerifyFalse()
    {
        var root = TestUtil.TempDir();
        var slot = Path.Combine(root, "slot");
        Directory.CreateDirectory(slot);
        var outside = Path.Combine(root, "outside.txt");
        File.WriteAllText(outside, "outside");
        File.WriteAllText(Path.Combine(slot, "real.txt"), "real");
        var hash = SlotIntegrity.ContentHash(slot);
        Assert.True(SlotIntegrity.Verify(slot, hash));
        File.CreateSymbolicLink(Path.Combine(slot, "link.txt"), outside);
        Assert.False(SlotIntegrity.Verify(slot, hash));
    }

    [Fact] // DS-P9-F17: ADS / reserved-device / trailing-dot manifest paths refuse
    public void P9F17_ManifestPath_AdsAndDeviceNames_Refused()
    {
        Assert.NotNull(Acp.Shared.Backup.BackupSnapshotStore.ValidateManifestPath("docs/notes.txt:payload"));
        Assert.NotNull(Acp.Shared.Backup.BackupSnapshotStore.ValidateManifestPath("docs/NUL"));
        Assert.NotNull(Acp.Shared.Backup.BackupSnapshotStore.ValidateManifestPath("docs/con.txt"));
        Assert.NotNull(Acp.Shared.Backup.BackupSnapshotStore.ValidateManifestPath("docs/file."));
        Assert.Null(Acp.Shared.Backup.BackupSnapshotStore.ValidateManifestPath("docs/notes.txt"));
    }

    [Fact] // DS-P9-F21: AddFile for a non-capturing snapshot throws BEFORE writing chunks
    public void P9F21_AddFile_UnknownSnapshot_WritesNoChunks()
    {
        var storage = new Acp.Shared.Backup.InMemoryBackupStorage();
        var store = new Acp.Shared.Backup.BackupSnapshotStore("tgt-1", storage);
        Assert.Throws<InvalidOperationException>(() =>
            store.AddFile("no-such-snapshot", "a.txt", Encoding.UTF8.GetBytes("data")));
    }

    // ---------- P7 (Windows half) ----------

    [Fact] // DS-P7-F22: hyphenated kill-switch names the floor too
    public void P7F22_FloorGuard_HyphenatedKillSwitch_Denied()
    {
        Assert.True(ConsentFloorGuard.IsDenied("rmm.kill-switch"));
        Assert.True(ConsentFloorGuard.IsDenied("rmm.kill switch"));
        Assert.False(ConsentFloorGuard.IsDenied("rmm.compliance.audit_pack.enabled"));
    }

    [Fact] // DS-P7-F8: revision, not document id, decides between same-target documents
    public void P7F8_EffectivePolicy_HigherRevisionWinsRegardlessOfId()
    {
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("z-doc", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["patch.ring"] = "stale" }, 1)).Allowed);
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("a-doc", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["patch.ring"] = "fresh" }, 2)).Allowed);
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev1", "co1"));
        Assert.Equal("fresh", eff.Get("patch.ring")!.Value);
    }

    [Fact] // DS-P7-F11: AddGroup with a null rules list refuses, never throws
    public void P7F11_AddGroup_NullRules_RefusedNotThrown()
    {
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddGroup(new GroupDefinition("g1", "G", null!));
        Assert.False(verdict.Allowed);
    }

    [Fact] // DS-P7-F17: Documents hands out copies — mutating one does not move live policy
    public void P7F17_Documents_ReturnsCopies()
    {
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("d1", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["patch.ring"] = "fleet" }, 1)).Allowed);
        var copy = engine.Documents.Single();
        ((Dictionary<string, string>)copy.Settings)["patch.ring"] = "hacked";
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev1", "co1"));
        Assert.Equal("fleet", eff.Get("patch.ring")!.Value);
    }

    [Fact] // DS-P7-F12/F23: unknown gate class denies; set_value is under the NEVER credential rule
    public void P7F12F23_PolicyEngine_UnknownGateClass_And_SetValueNever()
    {
        var engine = new PolicyEngine();
        var pairing = new Pairing("p1", "Agent", new HashSet<string> { Scopes.Observe, Scopes.Drive }, DateTimeOffset.UtcNow, null, null, false);
        var unknownGate = new ToolDescriptor("some_tool", "x", Scopes.Drive, SessionRequirement.Core, RiskTier.High, GateClass: "deletion");
        using var args = JsonDocument.Parse("{}");
        var verdict = engine.Evaluate(pairing, unknownGate, args.RootElement, TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(verdict.Allowed);
        Assert.Contains("gated:deletion", verdict.DenyReason);

        var setValue = new ToolDescriptor("set_value", "x", Scopes.Drive, SessionRequirement.Core, RiskTier.High);
        using var credArgs = JsonDocument.Parse("""{"target_is_credential_field":true}""");
        var never = engine.Evaluate(pairing, setValue, credArgs.RootElement, TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(never.Allowed);
        Assert.True(never.IsNeverRule);
    }
}
