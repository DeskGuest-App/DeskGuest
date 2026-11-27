using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Wake;

namespace DeskGuest.Tests;

/// <summary>Block G — the completeness sweep built (G-01..G-08)
/// plus the TOTAL POLICY CONTROL feature toggles every one of
/// them answers to. Test names cite the feature and the rule
/// they prove. Attack coverage lives in BlockGDestructionTests;
/// this file proves the features WORK as specified.</summary>
public class BlockGTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    // ---- shared world (the SessionTests fixture shape) ----

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

    private static string ActiveSession(World w, string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    // ---- TOTAL POLICY CONTROL: the toggle layer itself ----

    private static PolicyBundle BundleV2(string[]? disabled = null, string[]? required = null, int version = 2) => new(
        Version: version, ScopeId: "co1", TransportCeiling: new[] { "lan", "hub" }, TransportMode: "auto",
        PinnedVersion: null, UpdateDeferUntil: null, ForbidAiPairings: false, DisableRecording: false,
        UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "",
        DisabledFeatures: disabled, RequiredFeatures: required);

    [Fact]
    public void Policy_V2Bundle_TogglesVerify_AndGate()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var signed = PolicyBundleService.Sign(BundleV2(disabled: new[] { PolicyFeatures.WakeOnLan }), org);
        var svc = new PolicyBundleService();
        Assert.True(svc.Verify(signed, org.PublicKey, T0).Allowed);
        var enforcer = new PolicyEnforcer(signed);
        Assert.Equal("disabled", enforcer.FeatureState(PolicyFeatures.WakeOnLan));
        Assert.False(enforcer.CheckFeature(PolicyFeatures.WakeOnLan).Allowed);
        Assert.Equal("allowed", enforcer.FeatureState(PolicyFeatures.TcpTunnel));
        Assert.True(enforcer.CheckFeature(PolicyFeatures.TcpTunnel).Allowed);
    }

    [Fact]
    public void Policy_V1Bundle_CarryingToggles_Refuses()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var signed = PolicyBundleService.Sign(BundleV2(disabled: new[] { PolicyFeatures.WakeOnLan }, version: 1), org);
        Assert.False(new PolicyBundleService().Verify(signed, org.PublicKey, T0).Allowed);
    }

    [Fact]
    public void Policy_UnknownOrContradictoryToggle_Refuses()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var svc = new PolicyBundleService();
        var unknown = PolicyBundleService.Sign(BundleV2(disabled: new[] { "time_travel" }), org);
        Assert.False(svc.Verify(unknown, org.PublicKey, T0).Allowed);
        var both = PolicyBundleService.Sign(BundleV2(
            disabled: new[] { PolicyFeatures.Watermark }, required: new[] { PolicyFeatures.Watermark }), org);
        Assert.False(svc.Verify(both, org.PublicKey, T0).Allowed);
    }

    [Fact]
    public void Policy_TamperedToggle_BreaksSignature()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var signed = PolicyBundleService.Sign(BundleV2(), org);
        var tampered = signed with { DisabledFeatures = new[] { PolicyFeatures.Watermark } };
        Assert.False(new PolicyBundleService().Verify(tampered, org.PublicKey, T0).Allowed);
    }

    [Fact]
    public void Policy_ConsentFloor_HasNoToggle()
    {
        // §7.10: presence, STOP and the audit chain are not
        // features and can never enter the toggle set; asking the
        // enforcer about them fails closed.
        Assert.DoesNotContain("presence", PolicyFeatures.All);
        Assert.DoesNotContain("stop", PolicyFeatures.All);
        Assert.DoesNotContain("audit", PolicyFeatures.All);
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var enforcer = new PolicyEnforcer(PolicyBundleService.Sign(BundleV2(), org));
        Assert.False(enforcer.CheckFeature("presence").Allowed);
        Assert.Equal("disabled", enforcer.FeatureState("presence"));
        Assert.False(enforcer.FeatureRequired("presence"));
    }

    // ---- G-01 Wake-on-LAN ----

    private sealed class FakeWakeSender : IWakeSender
    {
        public List<(byte[] Packet, string Address, int Port)> Sent { get; } = new();
        public void Send(byte[] packet, string broadcastAddress, int port) =>
            Sent.Add((packet, broadcastAddress, port));
    }

    [Fact]
    public void G01_MagicPacket_CanonicalForm()
    {
        var mac = MagicPacket.ParseMac("00:11:22:33:44:55");
        Assert.NotNull(mac);
        Assert.Equal("00:11:22:33:44:55", MagicPacket.NormalizeMac(mac!));
        var packet = MagicPacket.Build(mac!);
        Assert.Equal(MagicPacket.PacketLength, packet.Length);
        Assert.All(packet.Take(6), b => Assert.Equal(0xFF, b));
        for (int i = 0; i < 16; i++)
            Assert.Equal(mac!, packet.Skip(6 + i * 6).Take(6).ToArray());
        // Dash form parses identically; junk refuses.
        Assert.Equal(mac!, MagicPacket.ParseMac("00-11-22-33-44-55"));
        Assert.Null(MagicPacket.ParseMac("00:11:22:33:44"));
        Assert.Null(MagicPacket.ParseMac("zz:11:22:33:44:55"));
        Assert.Null(MagicPacket.ParseMac(""));
        // Never wakeable: zero, broadcast, multicast.
        Assert.False(MagicPacket.IsWakeableMac(MagicPacket.ParseMac("00:00:00:00:00:00")!));
        Assert.False(MagicPacket.IsWakeableMac(MagicPacket.ParseMac("FF:FF:FF:FF:FF:FF")!));
        Assert.False(MagicPacket.IsWakeableMac(MagicPacket.ParseMac("01:00:5E:00:00:01")!));
        Assert.True(MagicPacket.IsWakeableMac(mac!));
    }

    [Fact]
    public void G01_WakeService_GatesAndSends()
    {
        var w = Setup();
        var sender = new FakeWakeSender();
        var wake = new WakeService(w.Roster, w.Enrollments, sender);
        // Registration is admin-gated: a plain user cannot enroll
        // a wake target; the company admin (or the trusted
        // in-process caller) can.
        Assert.False(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "ctrl"));
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        // A "use" holder wakes; the packet goes to the registered
        // broadcast on the wake port.
        var (sent, _) = wake.SendWake(w.DeviceId, "ctrl");
        Assert.True(sent);
        var call = Assert.Single(sender.Sent);
        Assert.Equal("192.168.1.255", call.Address);
        Assert.Equal(MagicPacket.WakePort, call.Port);
        Assert.Equal(102, call.Packet.Length);
        // No grant, no wake. Unknown device, no wake.
        Assert.False(wake.SendWake(w.DeviceId, "outsider").Sent);
        Assert.False(wake.SendWake("deadbeef", "ctrl").Sent);
        // Policy-disabled: the gate refuses before anything sends.
        var gated = new WakeService(w.Roster, w.Enrollments, sender,
            (_, _) => new PolicyVerdict(false, "disabled by test policy"));
        Assert.True(gated.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        Assert.False(gated.SendWake(w.DeviceId, "ctrl").Sent);
        Assert.Single(sender.Sent); // still exactly one packet overall
    }

    [Fact]
    public void G01_WakeForSession_RequestedOnly_AndRecorded()
    {
        var w = Setup();
        var sender = new FakeWakeSender();
        var wake = new WakeService(w.Roster, w.Enrollments, sender);
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        // A non-participant cannot wake for the session.
        Assert.False(wake.SendWakeForSession(w.Sessions, s!.Id, "outsider").Sent);
        // The initiator can; the wake lands on the session replay.
        Assert.True(wake.SendWakeForSession(w.Sessions, s.Id, "ctrl").Sent);
        Assert.Contains(w.Sessions.ListEvents(s.Id), e => e.Kind == "wake_sent");
        // Once live, waking is meaningless and refuses.
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.False(wake.SendWakeForSession(w.Sessions, s.Id, "ctrl").Sent);
    }

    [Fact]
    public void G01_WakeTargets_Persist_AndRevalidate()
    {
        var w = Setup();
        var wake = new WakeService(w.Roster, w.Enrollments, new FakeWakeSender());
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin"));
        var json = wake.ExportJson();
        var restored = new WakeService(w.Roster, w.Enrollments, new FakeWakeSender());
        Assert.Equal(1, restored.ImportJson(json));
        Assert.NotNull(restored.GetTarget(w.DeviceId));
        // A hand-edited store with an unwakeable MAC imports nothing.
        var evil = json.Replace("00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF");
        var restored2 = new WakeService(w.Roster, w.Enrollments, new FakeWakeSender());
        Assert.Equal(0, restored2.ImportJson(evil));
    }

    // ---- G-02 / G-03 / G-07 session surfaces ----

    [Fact]
    public void G02_BlankScreen_HostAndFloorOnly_NeverBeforeLive()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        // Not live yet: nobody can blank a requested session.
        Assert.False(w.Sessions.SetBlanked(s!.Id, true, "host"));
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        // An outsider cannot; the host can; the floor holder can.
        Assert.False(w.Sessions.SetBlanked(s.Id, true, "outsider"));
        Assert.True(w.Sessions.SetBlanked(s.Id, true, "host"));
        Assert.True(w.Sessions.GetSession(s.Id)!.Blanked);
        Assert.True(w.Sessions.SetBlanked(s.Id, false, "host"));
        Assert.True(w.Sessions.GrantFloor(s.Id, "ctrl", "host"));
        Assert.True(w.Sessions.SetBlanked(s.Id, true, "ctrl"));
        Assert.Contains(w.Sessions.ListEvents(s.Id), e => e.Kind == "blank_set");
        // Policy-disabled: enabling refuses, but clearing is the
        // host's escape hatch and is never policy-gated.
        w.Disabled.Add(PolicyFeatures.BlankScreen);
        Assert.True(w.Sessions.SetBlanked(s.Id, false, "host"));
        Assert.False(w.Sessions.SetBlanked(s.Id, true, "host"));
    }

    [Fact]
    public void G03_InputBlock_ActiveOnly_ReleasedByPauseAndEnd()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.SetInputBlocked(id, true, "host"));
        Assert.True(w.Sessions.GetSession(id)!.InputBlocked);
        // Pause releases the block (the person at the machine is
        // never left locked out of a paused session).
        Assert.True(w.Sessions.PauseSession(id, "ctrl"));
        Assert.False(w.Sessions.GetSession(id)!.InputBlocked);
        Assert.Contains(w.Sessions.ListEvents(id), e => e.Kind == "input_block_cleared");
        // And it cannot be set while paused (active-only).
        Assert.False(w.Sessions.SetInputBlocked(id, true, "host"));
    }

    [Fact]
    public void G07_Watermark_DerivedText_HostClearOnly_RequiredTrapsStart()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        // Settable from "requested" (by a host-side actor — here
        // the company admin); the text is DERIVED (session record
        // + roster), never caller-supplied.
        Assert.True(w.Sessions.SetWatermarked(s!.Id, true, "admin"));
        var spec = w.Sessions.GetWatermark(s.Id);
        Assert.NotNull(spec);
        Assert.Contains("Controller", spec!.Text);
        Assert.Contains(s.Id[..8], spec.Text);
        Assert.Contains("company-1", spec.Text);
        // A remote participant cannot clear it; the host can.
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.False(w.Sessions.SetWatermarked(s.Id, false, "ctrl"));
        Assert.True(w.Sessions.SetWatermarked(s.Id, false, "host"));
        // Required by policy: start refuses unwatermarked, and
        // NOBODY clears while the requirement stands.
        w.Required.Add(PolicyFeatures.Watermark);
        Assert.False(w.Sessions.StartSession(s.Id));
        Assert.True(w.Sessions.SetWatermarked(s.Id, true, "host"));
        Assert.False(w.Sessions.SetWatermarked(s.Id, false, "host"));
        Assert.True(w.Sessions.StartSession(s.Id));
    }

    [Fact]
    public void G02_G03_G07_EndCascade_ClearsAll()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.SetBlanked(id, true, "host"));
        Assert.True(w.Sessions.SetInputBlocked(id, true, "host"));
        Assert.True(w.Sessions.SetWatermarked(id, true, "host"));
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        var ended = w.Sessions.GetSession(id)!;
        Assert.False(ended.Blanked);
        Assert.False(ended.InputBlocked);
        Assert.False(ended.Watermarked);
    }

    // ---- G-05 in-session voice/video (call model) ----

    [Fact]
    public void G05_Call_Lifecycle_ConsentShaped()
    {
        var w = Setup();
        var id = ActiveSession(w);
        // Only participants call; one live call per session.
        Assert.Null(w.Sessions.StartCall(id, "outsider", "video"));
        var call = w.Sessions.StartCall(id, "ctrl", "video");
        Assert.NotNull(call);
        Assert.Equal("ringing", call!.State);
        Assert.Null(w.Sessions.StartCall(id, "host", "audio"));
        // The initiator cannot answer their own call — a call is
        // answered by the OTHER side (consent shape).
        Assert.False(w.Sessions.AnswerCall(call.Id, "ctrl"));
        Assert.True(w.Sessions.AnswerCall(call.Id, "host"));
        Assert.Equal("active", w.Sessions.GetLiveCall(id)!.State);
        Assert.True(w.Sessions.EndCall(call.Id, "ctrl"));
        Assert.Null(w.Sessions.GetLiveCall(id));
        // Policy-disabled: no call starts.
        w.Disabled.Add(PolicyFeatures.VoiceVideo);
        Assert.Null(w.Sessions.StartCall(id, "ctrl", "audio"));
    }

    [Fact]
    public void G05_Call_DiesWithSession()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var call = w.Sessions.StartCall(id, "ctrl", "audio");
        Assert.NotNull(call);
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        Assert.Null(w.Sessions.GetLiveCall(id));
        Assert.Equal("ended", w.Sessions.GetCall(call!.Id)!.State);
    }

    // ---- G-04 standalone file transfer ----

    [Fact]
    public void G04_StandaloneTransfer_LifecycleAndInvariants()
    {
        var w = Setup();
        var svc = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = svc.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "report.pdf", 100);
        Assert.NotNull(job);
        Assert.Equal("queued", job!.State);
        // No grant, no job; wrong scope, no job.
        Assert.Null(svc.CreateJob("company-1", w.DeviceId, "outsider", "to_host", "x.bin", 1));
        Assert.Null(svc.CreateJob("personal-1", w.DeviceId, "owner", "to_host", "x.bin", 1));
        // Progress is monotonic and bounded; only the initiator reports.
        Assert.False(svc.UpdateProgress(job.Id, 10, "host"));
        Assert.True(svc.UpdateProgress(job.Id, 50, "ctrl"));
        Assert.False(svc.UpdateProgress(job.Id, 40, "ctrl"));
        Assert.False(svc.UpdateProgress(job.Id, 101, "ctrl"));
        // "done" requires full bytes, through the legal transitions.
        Assert.True(svc.SetJobState(job.Id, "active", "ctrl"));
        Assert.False(svc.SetJobState(job.Id, "done", "ctrl"));
        Assert.True(svc.UpdateProgress(job.Id, 100, "ctrl"));
        Assert.True(svc.SetJobState(job.Id, "done", "ctrl"));
        // Terminal is terminal.
        Assert.False(svc.UpdateProgress(job.Id, 100, "ctrl"));
    }

    [Fact]
    public void G04_AuthorizationEvaporation_CancelsLiveJob()
    {
        var w = Setup();
        var svc = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = svc.CreateJob("company-1", w.DeviceId, "ctrl", "from_host", "logs.zip", 10);
        Assert.NotNull(job);
        // The device is revoked mid-flight: the next act re-reads
        // authorization, cancels the job on the spot, and refuses.
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        Assert.False(svc.UpdateProgress(job!.Id, 5, "ctrl"));
        Assert.Equal("cancelled", svc.GetJob(job.Id)!.State);
        Assert.Contains(svc.Events, e => e.Kind == "job_cancelled_authorization_lost");
    }

    // ---- G-06 local second factor ----

    [Fact]
    public void G06_RfcVectors_Base32AndHotp()
    {
        // RFC 4648 §10 test vectors, in the codec's canonical
        // UNPADDED form (padding is presentation; the decoder
        // accepts both — asserted by the round-trips in the
        // enrollment test).
        Assert.Equal("MY", Base32.Encode(Encoding.ASCII.GetBytes("f")));
        Assert.Equal("MZXQ", Base32.Encode(Encoding.ASCII.GetBytes("fo")));
        Assert.Equal("MZXW6", Base32.Encode(Encoding.ASCII.GetBytes("foo")));
        Assert.Equal("MZXW6YQ", Base32.Encode(Encoding.ASCII.GetBytes("foob")));
        Assert.Equal("MZXW6YTB", Base32.Encode(Encoding.ASCII.GetBytes("fooba")));
        Assert.Equal("MZXW6YTBOI", Base32.Encode(Encoding.ASCII.GetBytes("foobar")));
        // RFC 4226 Appendix D (secret = ASCII "12345678901234567890").
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        Assert.Equal("755224", Totp.Hotp(secret, 0));
        Assert.Equal("287082", Totp.Hotp(secret, 1));
        Assert.Equal("359152", Totp.Hotp(secret, 2));
        Assert.Equal("969429", Totp.Hotp(secret, 3));
    }

    [Fact]
    public void G06_TotpEnrollment_ConfirmThenVerify_ReplayDead()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var begin = svc.BeginTotpEnrollment("company-1", "ctrl");
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret);
        Assert.NotNull(secret);
        // A pending enrollment verifies NOTHING.
        Assert.False(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret!, T0), T0));
        // Confirm proves possession; the confirming step is consumed.
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret!, T0), T0));
        Assert.True(svc.HasActiveTotp("company-1", "ctrl"));
        Assert.False(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret!, T0), T0)); // replay
        var t1 = T0.AddSeconds(30);
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret!, t1), t1));
        // An AI user holds no factor (D9); a suspended user verifies nothing.
        Assert.Null(svc.BeginTotpEnrollment("company-1", "ai-1"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", true));
        var t2 = T0.AddSeconds(60);
        Assert.False(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret!, t2), t2));
    }

    [Fact]
    public void G06_PasskeyAssertion_Verifies_AndCounterIsMonotonic()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(false);
        var credId = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        Assert.True(svc.RegisterPasskey("company-1", "ctrl", credId,
            Convert.ToBase64String(p.Q.X!), Convert.ToBase64String(p.Q.Y!)));

        (byte[] AuthData, string ClientJson, byte[] Sig) MakeAssertion(uint counter, string challenge)
        {
            const string rpId = "deskguest.local";
            var clientJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge +
                "\",\"origin\":\"https://deskguest.local\",\"crossOrigin\":false}";
            var authData = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authData, 0);
            authData[32] = 0x01; // user-presence flag
            BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33, 4), counter);
            var signed = authData.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(clientJson))).ToArray();
            var sig = ecdsa.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return (authData, clientJson, sig);
        }

        // Block H (F12): challenges are SERVICE-ISSUED — the
        // ceremony runs against the challenge IssuePasskeyChallenge
        // handed out for this user, never an attacker-chosen one.
        var challenge = svc.IssuePasskeyChallenge("company-1", "ctrl", T0);
        Assert.NotNull(challenge);
        var a1 = MakeAssertion(1, challenge!);
        Assert.True(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            a1.AuthData, a1.ClientJson, a1.Sig, challenge!, "deskguest.local", T0));
        // The same counter again (a cloned authenticator) refuses.
        Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            a1.AuthData, a1.ClientJson, a1.Sig, challenge!, "deskguest.local", T0));
        // A wrong challenge refuses even with a fresh counter.
        var a2 = MakeAssertion(2, "AAAA");
        Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", credId,
            a2.AuthData, a2.ClientJson, a2.Sig, challenge!, "deskguest.local", T0));
    }

    // ---- G-08 session tunnels ----

    [Fact]
    public void G08_Tunnel_SessionBound_Lifecycle()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        // An outsider cannot open; a wildcard target is not a destination.
        Assert.Null(tunnels.Open(id, "outsider", "192.168.1.10", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "0.0.0.0", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "192.168.1.10", 0, 18080));
        var t = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(t);
        // Same listen port twice on one session refuses; a second
        // distinct tunnel is fine.
        Assert.Null(tunnels.Open(id, "host", "192.168.1.11", 80, 18080));
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.11", 80, 18081));
        // The opener closes; a random participant cannot.
        Assert.False(tunnels.Close(t!.Id, "peer"));
        Assert.True(tunnels.Close(t.Id, "host"));
        Assert.False(tunnels.Close(t.Id, "host")); // already closed
    }

    [Fact]
    public void G08_Tunnel_DiesWithSession_AndImportKeepsItDead()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        var t = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(t);
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        // The per-act re-read closes it on the spot.
        Assert.False(tunnels.Close(t!.Id, "host"));
        Assert.Equal("closed", tunnels.GetTunnel(t.Id)!.State);
        // An exported open tunnel imports CLOSED when its session
        // is not live in the importing store (F11 rule).
        var w2 = Setup();
        var id2 = ActiveSession(w2);
        var tunnels2 = new SessionTunnelService(w2.Sessions, w2.Roster);
        var t2 = tunnels2.Open(id2, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(t2);
        var json = tunnels2.ExportJson();
        var fresh = new SessionTunnelService(w2.Sessions, w2.Roster);
        Assert.Equal(1, fresh.ImportJson(json));
        Assert.Equal("open", fresh.GetTunnel(t2!.Id)!.State); // session live here
        var dead = new SessionTunnelService(w.Sessions, w.Roster); // w's session ended
        Assert.Equal(1, dead.ImportJson(json));
        Assert.Equal("closed", dead.GetTunnel(t2.Id)!.State);
    }
}
