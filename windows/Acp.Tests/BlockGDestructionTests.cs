using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Acp.Shared.Enrollment;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Wake;

namespace Acp.Tests;

/// <summary>Block G — destruction pass. Every test here is an
/// ATTACK on a Block G surface: forged actors, stale authority,
/// hand-edited stores, replayed factors, policy downgrade edits.
/// The surface holds if the attack refuses AND leaves no partial
/// state. Breaks found by this file convert to fixes + ledger
/// entries (DESTRUCTION-LEDGER.md), never to quiet test edits.</summary>
public class BlockGDestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public SessionService Sessions { get; set; } = null!;
        public required string DeviceId { get; init; }
        public HashSet<string> Disabled { get; } = new();
        public HashSet<string> Required { get; } = new();
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("outsider", "company-1", "Outsider", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        var w = new World { Enrollments = enrollments, Roster = roster, Sessions = null!, DeviceId = device!.DeviceId };
        w.Sessions = new SessionService(roster, enrollments,
            (scopeId, key) => w.Disabled.Contains(key)
                ? new PolicyVerdict(false, $"feature '{key}' disabled by test policy")
                : new PolicyVerdict(true, "permitted by test policy"),
            (scopeId, key) => w.Required.Contains(key));
        return w;
    }

    private static string ActiveSession(World w)
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    // ---- policy downgrade attacks ----

    [Fact]
    public void Attack_Policy_StripDisabledToggle_BreaksSignature()
    {
        // Sign a bundle that disables watermark, then hand-edit
        // the toggle OUT to silently re-enable the feature. The
        // toggles live inside the signed body: the edit refuses.
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var unsigned = new PolicyBundle(
            Version: 2, ScopeId: "co1", TransportCeiling: new[] { "lan", "hub" }, TransportMode: "auto",
            PinnedVersion: null, UpdateDeferUntil: null, ForbidAiPairings: false, DisableRecording: false,
            UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "",
            DisabledFeatures: new[] { PolicyFeatures.Watermark });
        var signed = PolicyBundleService.Sign(unsigned, org);
        var stripped = signed with { DisabledFeatures = Array.Empty<string>() };
        Assert.False(new PolicyBundleService().Verify(stripped, org.PublicKey, T0).Allowed);
        // Downgrade the format version to dodge the v2 body: the
        // v1 body differs from what was signed — refuses too.
        var downgraded = signed with { Version = 1 };
        Assert.False(new PolicyBundleService().Verify(downgraded, org.PublicKey, T0).Allowed);
    }

    [Fact]
    public void Attack_Policy_ConsentFloorToggle_RefusesAtVerification()
    {
        // A bundle that tries to toggle the consent floor itself
        // ("presence") names a key outside the closed set — the
        // bundle refuses whole, it is not partially honored.
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var unsigned = new PolicyBundle(
            Version: 2, ScopeId: "co1", TransportCeiling: new[] { "lan", "hub" }, TransportMode: "auto",
            PinnedVersion: null, UpdateDeferUntil: null, ForbidAiPairings: false, DisableRecording: false,
            UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "",
            DisabledFeatures: new[] { "presence" });
        var signed = PolicyBundleService.Sign(unsigned, org);
        Assert.False(new PolicyBundleService().Verify(signed, org.PublicKey, T0).Allowed);
    }

    // ---- G-01 attacks ----

    private sealed class FakeWakeSender : IWakeSender
    {
        public int Count;
        public void Send(byte[] packet, string broadcastAddress, int port) => Count++;
    }

    [Fact]
    public void Attack_G01_SuspendedOrRevoked_NeverWakes()
    {
        var w = Setup();
        var sender = new FakeWakeSender();
        var wake = new WakeService(w.Roster, w.Enrollments, sender);
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        // Suspended actor: the grant row still exists; the wake refuses.
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", true));
        Assert.False(wake.SendWake(w.DeviceId, "ctrl").Sent);
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", false));
        // Revoked device: never woken, even for a live grant holder.
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        Assert.False(wake.SendWake(w.DeviceId, "ctrl").Sent);
        Assert.Equal(0, sender.Count);
        // An unwakeable MAC cannot even be registered.
        var w2 = Setup();
        var wake2 = new WakeService(w2.Roster, w2.Enrollments, sender);
        Assert.False(wake2.RegisterTarget(w2.DeviceId, "FF:FF:FF:FF:FF:FF", "192.168.1.255", "admin"));
        Assert.False(wake2.RegisterTarget(w2.DeviceId, "not-a-mac", "192.168.1.255", "admin"));
    }

    // ---- G-02 / G-03 attacks ----

    [Fact]
    public void Attack_G02_SuspendedFloorHolder_StaleRowConfersNothing()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", true));
        // Ctrl still HOLDS the floor on paper; suspension re-read refuses.
        Assert.False(w.Sessions.SetBlanked(id, true, "ctrl"));
        Assert.False(w.Sessions.GetSession(id)!.Blanked);
    }

    [Fact]
    public void Attack_G02_BlankNeverTrapsTheKillPath()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.SetBlanked(id, true, "host"));
        Assert.True(w.Sessions.SetInputBlocked(id, true, "host"));
        // Blanked + input-blocked, the session still ends on
        // demand (the model-level form of "STOP always works"):
        // presence and STOP are not the session record's to hide.
        Assert.True(w.Sessions.EndSession(id, "host"));
        Assert.Equal("ended", w.Sessions.GetSession(id)!.State);
    }

    [Fact]
    public void Attack_G03_ExHolderCannotBlockAfterFloorTakenBack()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Sessions.TakeFloorBack(id, "host"));
        Assert.False(w.Sessions.SetInputBlocked(id, true, "ctrl"));
        Assert.False(w.Sessions.GetSession(id)!.InputBlocked);
    }

    // ---- G-04 attacks ----

    [Fact]
    public void Attack_G04_TransitionSkip_AndForgedProgress()
    {
        var w = Setup();
        var svc = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = svc.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "a.bin", 10);
        Assert.NotNull(job);
        // queued → done directly is not in the transition set.
        Assert.False(svc.SetJobState(job!.Id, "done", "ctrl"));
        // A different user cannot move or report on the job at all.
        Assert.False(svc.SetJobState(job.Id, "active", "peer"));
        Assert.False(svc.UpdateProgress(job.Id, 10, "peer"));
        Assert.Equal("queued", svc.GetJob(job.Id)!.State);
        Assert.Equal(0, svc.GetJob(job.Id)!.TransferredBytes);
    }

    [Fact]
    public void Attack_G04_HandEditedStore_DropsImpossibleJobs()
    {
        var w = Setup();
        var svc = new StandaloneTransferService(w.Roster, w.Enrollments);
        // "done" without full bytes; negative progress; unknown
        // state — each entry drops at import, none resurrects.
        var evil = "[" +
            "{\"Id\":\"j1\",\"ScopeId\":\"company-1\",\"DeviceId\":\"" + w.DeviceId + "\",\"InitiatorUserId\":\"ctrl\",\"Direction\":\"to_host\",\"Name\":\"a\",\"SizeBytes\":10,\"TransferredBytes\":5,\"State\":\"done\"}," +
            "{\"Id\":\"j2\",\"ScopeId\":\"company-1\",\"DeviceId\":\"" + w.DeviceId + "\",\"InitiatorUserId\":\"ctrl\",\"Direction\":\"to_host\",\"Name\":\"b\",\"SizeBytes\":10,\"TransferredBytes\":-1,\"State\":\"active\"}," +
            "{\"Id\":\"j3\",\"ScopeId\":\"company-1\",\"DeviceId\":\"" + w.DeviceId + "\",\"InitiatorUserId\":\"ctrl\",\"Direction\":\"to_host\",\"Name\":\"c\",\"SizeBytes\":10,\"TransferredBytes\":0,\"State\":\"teleported\"}" +
            "]";
        Assert.Equal(0, svc.ImportJson(evil));
        Assert.Equal(0, svc.LiveJobCount());
    }

    // ---- G-05 attacks ----

    [Fact]
    public void Attack_G05_ForgedCallActors_AndDeadSessions()
    {
        var w = Setup();
        var id = ActiveSession(w);
        // Unknown call kind refuses (no silent coercion to audio).
        Assert.Null(w.Sessions.StartCall(id, "ctrl", "smoke-signals"));
        var call = w.Sessions.StartCall(id, "ctrl", "audio");
        Assert.NotNull(call);
        // A non-participant cannot answer or end the call.
        Assert.False(w.Sessions.AnswerCall(call!.Id, "outsider"));
        Assert.False(w.Sessions.EndCall(call.Id, "outsider"));
        Assert.Equal("ringing", w.Sessions.GetLiveCall(id)!.State);
        // After the session ends, no call can start on its corpse.
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        Assert.Null(w.Sessions.StartCall(id, "ctrl", "audio"));
        Assert.False(w.Sessions.AnswerCall(call.Id, "host"));
    }

    // ---- G-06 attacks ----

    private sealed class ReversingProtector : ISecretProtector
    {
        public string Name => "test-reversing";
        public bool IsRealProtection => true;
        public string Protect(string plaintext) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext).Reverse().ToArray());
        public string Unprotect(string protectedText) =>
            Encoding.UTF8.GetString(Convert.FromBase64String(protectedText).Reverse().ToArray());
    }

    [Fact]
    public void Attack_G06_OldCodes_AdminTheft_AndSealedStore()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new ReversingProtector());
        var begin = svc.BeginTotpEnrollment("company-1", "ctrl");
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret)!;
        // A code two steps old is outside the ±1 window.
        var old = T0.AddSeconds(-60);
        Assert.False(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret, old), T0));
        Assert.False(svc.HasActiveTotp("company-1", "ctrl")); // still pending, verifies nothing
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret, T0), T0));
        // Removal demands the owner's own live code, or a company
        // admin's act: a wrong code refuses, and a peer cannot
        // administer someone else's factor away.
        Assert.False(svc.RemoveTotp("company-1", "ctrl", Totp.At(secret, T0.AddDays(1)), T0.AddSeconds(30)));
        Assert.True(svc.HasActiveTotp("company-1", "ctrl"));
        Assert.False(svc.RemoveTotpByAdmin("company-1", "ctrl", "peer"));
        Assert.True(svc.RemoveTotpByAdmin("company-1", "ctrl", "admin"));
        Assert.False(svc.HasActiveTotp("company-1", "ctrl"));

        // Sealed store: enroll under one protector, import the
        // export under another — the seal does not open, the
        // factor verifies nothing.
        var svcA = new SecondFactorService(w.Roster, new ReversingProtector());
        var beginA = svcA.BeginTotpEnrollment("company-1", "host");
        Assert.NotNull(beginA);
        var secretA = Base32.Decode(beginA!.Value.Base32Secret)!;
        Assert.True(svcA.ConfirmTotpEnrollment("company-1", "host", Totp.At(secretA, T0), T0));
        var exported = svcA.ExportJson();
        Assert.DoesNotContain(beginA.Value.Base32Secret, exported);
        var svcB = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        svcB.ImportJson(exported);
        Assert.False(svcB.VerifyTotp("company-1", "host", Totp.At(secretA, T0.AddSeconds(30)), T0.AddSeconds(30)));
    }

    [Fact]
    public void Attack_G06_Passkey_FlagAndRpAttacks()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(false);
        var credId = Convert.ToBase64String(new byte[] { 7, 7, 7 });
        Assert.True(svc.RegisterPasskey("company-1", "ctrl", credId,
            Convert.ToBase64String(p.Q.X!), Convert.ToBase64String(p.Q.Y!)));
        // Block H (F12): every ceremony runs against a freshly
        // SERVICE-ISSUED challenge (returned as Item4) — a failed
        // attempt burns its challenge, so each attack below mints
        // its own, exactly as a real ceremony would.
        (byte[], string, byte[], string) Make(byte flags, string rpId, uint counter)
        {
            var challenge = svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
            var clientJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge +
                "\",\"origin\":\"https://" + rpId + "\",\"crossOrigin\":false}";
            var authData = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authData, 0);
            authData[32] = flags;
            BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33, 4), counter);
            var signed = authData.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(clientJson))).ToArray();
            return (authData, clientJson,
                ecdsa.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                challenge);
        }

        // User-presence flag clear: a silent, unattended assertion refuses.
        var noUp = Make(0x00, "acp.local", 1);
        Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            noUp.Item1, noUp.Item2, noUp.Item3, noUp.Item4, "acp.local", T0));
        // An assertion minted for a different relying party refuses here.
        var wrongRp = Make(0x01, "evil.example", 1);
        Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            wrongRp.Item1, wrongRp.Item2, wrongRp.Item3, wrongRp.Item4, "acp.local", T0));
        // The genuine assertion still verifies afterwards (the
        // attacks consumed no counter).
        var good = Make(0x01, "acp.local", 1);
        Assert.True(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            good.Item1, good.Item2, good.Item3, good.Item4, "acp.local", T0));
    }

    // ---- G-08 attacks ----

    [Fact]
    public void Attack_G08_CrossScopeActor_AndMalformedTargets()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        // The personal-scope owner is nobody on this company session.
        Assert.Null(tunnels.Open(id, "owner", "192.168.1.10", 8080, 18080));
        // Malformed targets refuse: whitespace/control smuggling,
        // privileged listen ports, dead sessions.
        Assert.Null(tunnels.Open(id, "host", "192.168.1.10 --evil", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "192.168.1.10", 8080, 80));
        Assert.Null(tunnels.Open(id, "host", "::", 8080, 18080));
        var s2 = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s2);
        Assert.Null(tunnels.Open(s2!.Id, "host", "192.168.1.10", 8080, 18080)); // merely requested
        Assert.Empty(tunnels.ListOpen());
    }

    [Fact]
    public void Attack_G08_Sweep_ClosesEverythingOnSessionEnd()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.10", 8080, 18080));
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.11", 80, 18081));
        Assert.Equal(2, tunnels.CloseForSession(id));
        Assert.Empty(tunnels.ListOpen());
        Assert.Equal(0, tunnels.CloseForSession(id)); // idempotent
    }

    // ---- D38 review fix round (2026-11-20) -------------------
    // The independent review CRACKED the surfaces below; each test
    // pins the fix. Ledger: DG-G-09..DG-G-14.

    private static SessionService FreshSessions(World w) => new(w.Roster, w.Enrollments,
        (scopeId, key) => w.Disabled.Contains(key)
            ? new PolicyVerdict(false, $"feature '{key}' disabled by test policy")
            : new PolicyVerdict(true, "permitted by test policy"),
        (scopeId, key) => w.Required.Contains(key));

    [Fact]
    public void Fix_F3_ForgedHostRole_DemotedOnImport()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.SetWatermarked(id, true, "host"));
        var json = w.Sessions.ExportJson();
        // Forge: the controller rewrites their own participant row
        // to "host" in the store file.
        var forged = json.Replace("\"UserId\":\"ctrl\",\"Role\":\"controller\"",
            "\"UserId\":\"ctrl\",\"Role\":\"host\"");
        Assert.NotEqual(json, forged);
        var fresh = FreshSessions(w);
        fresh.ImportJson(forged);
        var participants = fresh.ListParticipants(id);
        Assert.Equal("watcher", participants.Single(p => p.UserId == "ctrl").Role); // demoted
        Assert.Equal("host", participants.Single(p => p.UserId == "host").Role);    // genuine host keeps it
        // The forged row confers nothing: ctrl cannot clear the
        // watermark; the genuine host can.
        Assert.False(fresh.SetWatermarked(id, false, "ctrl"));
        Assert.True(fresh.SetWatermarked(id, false, "host"));
    }

    [Fact]
    public void Fix_F3_LiveImport_DeviceRevoked_EndsAtImport()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var json = w.Sessions.ExportJson();
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        var fresh = FreshSessions(w);
        fresh.ImportJson(json);
        Assert.Equal("ended", fresh.GetSession(id)!.State);
    }

    [Fact]
    public void Fix_F4_Reenrollment_RequiresCurrentCode_OldFactorSurvives()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var begin = svc.BeginTotpEnrollment("company-1", "ctrl");
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret)!;
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret, T0), T0));
        // A hijacked session tries to replace the factor with an
        // attacker-known secret: no current code, no replacement —
        // and a WRONG code is no better.
        Assert.Null(svc.BeginTotpEnrollment("company-1", "ctrl"));
        Assert.Null(svc.BeginTotpEnrollment("company-1", "ctrl", "xxxxxx", T0.AddSeconds(30)));
        Assert.True(svc.HasActiveTotp("company-1", "ctrl"));
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, T0.AddSeconds(30)), T0.AddSeconds(30)));
        // The owner re-enrolls WITH a current code (consumed by
        // the authorization): the old factor keeps working until
        // the new one confirms — no factor-less window.
        var begin2 = svc.BeginTotpEnrollment("company-1", "ctrl",
            Totp.At(secret, T0.AddSeconds(60)), T0.AddSeconds(60));
        Assert.NotNull(begin2);
        Assert.True(svc.HasActiveTotp("company-1", "ctrl"));
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, T0.AddSeconds(90)), T0.AddSeconds(90)));
        var secret2 = Base32.Decode(begin2!.Value.Base32Secret)!;
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret2, T0.AddSeconds(120)), T0.AddSeconds(120)));
        // After confirmation the old secret is dead, the new one lives.
        Assert.False(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, T0.AddSeconds(150)), T0.AddSeconds(150)));
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret2, T0.AddSeconds(150)), T0.AddSeconds(150)));
    }

    [Fact]
    public void Fix_F5_TunnelReads_EnforceSessionLiveness()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        var t = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(t);
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        // No Close call happens: the READS themselves must not
        // report a live tunnel over a dead session.
        Assert.Empty(tunnels.ListOpen());
        Assert.Equal("closed", tunnels.GetTunnel(t!.Id)!.State);
    }

    [Fact]
    public void Fix_F9_Tunnel_AiRefused_PivotTargetsRefused()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        // An AI holds no tunnel authority (D9): even WITH the
        // floor deliberately granted, the AI cannot open — while
        // a human floor holder can, proving the refusal is the
        // AI rule and not the floor rule.
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "watcher", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ai-1", "host"));
        Assert.Null(tunnels.Open(id, "ai-1", "192.168.1.10", 8080, 18080));
        Assert.True(w.Sessions.AddParticipant(id, "peer", "watcher", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "peer", "host"));
        Assert.NotNull(tunnels.Open(id, "peer", "192.168.1.10", 8080, 18082));
        // The endpoint's own loopback / link-local space is not a
        // tunnel destination (the pivot the review named).
        Assert.Null(tunnels.Open(id, "host", "127.0.0.1", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "localhost", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "::1", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "169.254.10.10", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "fe80::1", 8080, 18080));
        // An ordinary LAN destination still opens.
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.10", 8080, 18080));
    }

    [Fact]
    public void Fix_F10_ImportedTotpCounter_CannotRollBack()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var now0 = DateTimeOffset.UtcNow;
        var begin = svc.BeginTotpEnrollment("company-1", "ctrl");
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret)!;
        var usedCode = Totp.At(secret, now0);
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", usedCode, now0));
        // Hand-edit the store: roll the accepted-step counter back
        // to -1 so the just-used code would verify again.
        var forged = Regex.Replace(svc.ExportJson(), "\"LastAcceptedStep\":-?\\d+", "\"LastAcceptedStep\":-1");
        var fresh = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        fresh.ImportJson(forged);
        Assert.True(fresh.HasActiveTotp("company-1", "ctrl"));
        Assert.False(fresh.VerifyTotp("company-1", "ctrl", usedCode, now0)); // replay stays dead
        // The factor is not bricked: a future code verifies.
        Assert.True(fresh.VerifyTotp("company-1", "ctrl",
            Totp.At(secret, now0.AddSeconds(120)), now0.AddSeconds(120)));
    }

    [Fact]
    public void Fix_F10_ImportedPasskey_OffCurvePointDropped()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var junk = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray());
        var json = "{\"Totp\":[],\"Passkeys\":[{\"ScopeId\":\"company-1\",\"UserId\":\"ctrl\"," +
            "\"CredentialIdBase64\":\"" + Convert.ToBase64String(new byte[] { 3, 3 }) + "\"," +
            "\"PublicKeyXBase64\":\"" + junk + "\",\"PublicKeyYBase64\":\"" + junk + "\"," +
            "\"SignCount\":0,\"CreatedUtc\":\"2026-11-20T12:00:00+00:00\"}],\"Events\":null}";
        Assert.Equal(0, svc.ImportJson(json));
        Assert.Equal(0, svc.Counts().Passkeys);
    }

    [Fact]
    public void Fix_F11_CallAnswer_InitiatorAndNonParticipantRefused()
    {
        var w = Setup();
        var id = ActiveSession(w);
        // The host starts a call: the host cannot answer their OWN
        // call (the pre-fix host-side branch allowed exactly that).
        var own = w.Sessions.StartCall(id, "host", "audio");
        Assert.NotNull(own);
        Assert.False(w.Sessions.AnswerCall(own!.Id, "host"));
        Assert.True(w.Sessions.AnswerCall(own.Id, "ctrl"));
        Assert.True(w.Sessions.EndCall(own.Id, "ctrl"));
        // A company admin who is NOT a participant cannot answer
        // (join) someone else's call.
        var call = w.Sessions.StartCall(id, "ctrl", "audio");
        Assert.NotNull(call);
        Assert.False(w.Sessions.AnswerCall(call!.Id, "admin"));
        Assert.True(w.Sessions.AnswerCall(call.Id, "host"));
    }

    [Fact]
    public void Fix_F8_Resume_RequiresWatermarkWhenPolicyRequires()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.PauseSession(id, "ctrl"));
        w.Required.Add(PolicyFeatures.Watermark);
        // The required-watermark trap guards RESUME too, not only
        // the first start.
        Assert.False(w.Sessions.ResumeSession(id, "ctrl"));
        Assert.True(w.Sessions.SetWatermarked(id, true, "host"));
        Assert.True(w.Sessions.ResumeSession(id, "ctrl"));
    }

    [Fact]
    public void Fix_F2_EnterpriseGate_ScopeIsolated()
    {
        var w = Setup();
        var dir = TestUtil.TempDir();
        try
        {
            var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
            var issued = DateTimeOffset.UtcNow.AddHours(-1);
            var unsigned = new PolicyBundle(2, "company-1", new[] { "lan", "hub" }, "auto",
                null, null, false, false, "business_hours", issued, issued.AddDays(30), "",
                new[] { PolicyFeatures.WakeOnLan }, null);
            var signed = PolicyBundleService.Sign(unsigned, org);
            File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), JsonSerializer.Serialize(signed));
            File.WriteAllText(Path.Combine(dir, "policy-orgkey.txt"), Convert.ToBase64String(org.PublicKey));
            var svc = new Acp.Core.Services.EnterpriseService(dir, w.Roster);
            Assert.Contains("loaded", svc.PolicyState);
            // The bundle disables wake in ITS scope only.
            Assert.False(svc.CheckFeature("company-1", PolicyFeatures.WakeOnLan).Allowed);
            Assert.True(svc.CheckFeature("personal-1", PolicyFeatures.WakeOnLan).Allowed);
            Assert.True(svc.CheckFeature("personal-1", PolicyFeatures.TcpTunnel).Allowed);
            // The key-only form still means "the bundle's own scope".
            Assert.False(svc.CheckFeature(PolicyFeatures.WakeOnLan).Allowed);
            Assert.False(svc.FeatureRequired("personal-1", PolicyFeatures.WakeOnLan));
        }
        finally { try { Directory.Delete(dir, recursive: true); } catch { } }
    }

    [Fact]
    public void Fix_F7_Standalone_ActiveImportFails_AdminCanCancel()
    {
        var w = Setup();
        var svc = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = svc.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "f.bin", 100);
        Assert.NotNull(job);
        Assert.True(svc.SetJobState(job!.Id, "active", "ctrl"));
        // A job stored "active" restores FAILED — its byte leg did
        // not survive the restart; the record must not claim a
        // transfer is moving when nothing is moving it.
        var fresh = new StandaloneTransferService(w.Roster, w.Enrollments);
        fresh.ImportJson(svc.ExportJson());
        Assert.Equal("failed", fresh.GetJob(job.Id)!.State);
        // Identity-less rows drop at import, terminal or not.
        var blanked = svc.ExportJson().Replace("\"ScopeId\":\"company-1\"", "\"ScopeId\":\"\"");
        var fresh2 = new StandaloneTransferService(w.Roster, w.Enrollments);
        Assert.Equal(0, fresh2.ImportJson(blanked));
        // The device-side stop: a peer cannot cancel, a live
        // company admin of the scope can.
        var job2 = svc.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "g.bin", 10);
        Assert.NotNull(job2);
        Assert.False(svc.CancelJob(job2!.Id, "peer"));
        Assert.True(svc.CancelJob(job2.Id, "admin"));
        Assert.Equal("cancelled", svc.GetJob(job2.Id)!.State);
    }

    [Fact]
    public void Fix_F1_WakeEvents_PersistAndSinkFires()
    {
        var w = Setup();
        var sink = new List<string>();
        var sender = new FakeWakeSender();
        var wake = new WakeService(w.Roster, w.Enrollments, sender, null,
            (kind, actor, detail) => sink.Add(kind));
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        Assert.True(wake.SendWake(w.DeviceId, "ctrl").Sent);
        // The chained-audit sink saw the acts as they happened.
        Assert.Contains("wake_target_registered", sink);
        Assert.Contains("wake_sent", sink);
        // And the events themselves survive the store round trip.
        var restored = new WakeService(w.Roster, w.Enrollments, new FakeWakeSender());
        restored.ImportJson(wake.ExportJson());
        Assert.Equal(wake.Events.Count, restored.Events.Count);
        Assert.True(restored.Events.Count >= 2);
    }
}
