using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

// RMM-03 — Endpoint Takeover Prevention: signed commands,
// endpoint-verified. Test names cite the requirement they prove.
public class Rmm03Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private sealed record Rig(DeviceIdentity Customer, SignedCommandSigner Signer,
        CustomerCommandKeyRing Ring, SignedCommandVerifier Verifier, ChainedAuditLog Audit, SignedCommandGate Gate);

    private static Rig NewRig()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var audit = new ChainedAuditLog();
        var verifier = new SignedCommandVerifier(ring);
        return new Rig(customer, new SignedCommandSigner(customer), ring, verifier, audit,
            new SignedCommandGate(verifier, audit));
    }

    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void RMM03_SignedEnvelope_Verifies_AndReturnsPayload()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hello"), T0, TimeSpan.FromMinutes(5));
        var v = rig.Verifier.Verify(env, T0.AddSeconds(30), SignedCommandClasses.ShellExec);
        Assert.True(v.Allowed, v.Reason);
        Assert.Equal("echo hello", Encoding.UTF8.GetString(v.Payload!));
    }

    [Fact]
    public void RMM03_UnsignedCommand_Refused()
    {
        var rig = NewRig();
        var v = rig.Verifier.Verify(null, T0);
        Assert.False(v.Allowed);
        Assert.Contains("unsigned", v.Reason);
    }

    [Fact]
    public void RMM03_AlteredPayload_Refused()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo safe"), T0, TimeSpan.FromMinutes(5));
        var tampered = env with { PayloadBase64 = Convert.ToBase64String(Bytes("rm -rf /")) };
        var v = rig.Verifier.Verify(tampered, T0.AddSeconds(10));
        Assert.False(v.Allowed);
        Assert.Contains("hash mismatch", v.Reason);
    }

    [Fact]
    public void RMM03_AlteredClass_Refused()
    {
        var rig = NewRig();
        // Sign a harmless class, then relabel it as shell execution:
        // the class is inside the signed canonical body, so the
        // signature itself breaks.
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery, Bytes("{}"), T0, TimeSpan.FromMinutes(5));
        var relabelled = env with { CommandClass = SignedCommandClasses.ShellExec };
        var v = rig.Verifier.Verify(relabelled, T0.AddSeconds(10));
        Assert.False(v.Allowed);
    }

    [Fact]
    public void RMM03_ForgedSignature_WrongKey_Refused()
    {
        var rig = NewRig();
        var attacker = NewIdentity(); // the compromised hub's own key
        var forged = new SignedCommandSigner(attacker).Sign(
            SignedCommandClasses.ShellExec, Bytes("echo pwned"), T0, TimeSpan.FromMinutes(5));
        // The attacker's key id is not in the customer ring at all.
        Assert.False(rig.Verifier.Verify(forged, T0.AddSeconds(10)).Allowed);
        // Even relabelled with the customer's key id, the signature fails.
        var relabelled = forged with { KeyId = rig.Signer.KeyId };
        Assert.False(rig.Verifier.Verify(relabelled, T0.AddSeconds(10)).Allowed);
    }

    [Fact]
    public void RMM03_ExpiredCommand_Refused()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"), T0, TimeSpan.FromMinutes(1));
        Assert.False(rig.Verifier.Verify(env, T0.AddMinutes(2)).Allowed);
    }

    [Fact]
    public void RMM03_FutureDatedCommand_Refused()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"), T0.AddHours(1), TimeSpan.FromMinutes(5));
        Assert.False(rig.Verifier.Verify(env, T0).Allowed);
    }

    [Fact]
    public void RMM03_UnknownClass_Refused_AndSignerRefusesToMint()
    {
        var rig = NewRig();
        Assert.Throws<ArgumentException>(() =>
            rig.Signer.Sign("teleport_device", Bytes("x"), T0, TimeSpan.FromMinutes(1)));
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("x"), T0, TimeSpan.FromMinutes(5));
        var weird = env with { CommandClass = "teleport_device" };
        Assert.False(rig.Verifier.Verify(weird, T0.AddSeconds(5)).Allowed);
    }

    [Fact]
    public void RMM03_WrongPathClass_Refused()
    {
        var rig = NewRig();
        // A genuine, validly signed POLICY envelope presented to the
        // SHELL path: class binding stops cross-path confusion.
        var env = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery, Bytes("{}"), T0, TimeSpan.FromMinutes(5));
        var v = rig.Verifier.Verify(env, T0.AddSeconds(5), SignedCommandClasses.ShellExec);
        Assert.False(v.Allowed);
        Assert.Contains("does not match", v.Reason);
    }

    [Fact]
    public void RMM03_ReplayedEnvelope_Refused()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo once"), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Verifier.Verify(env, T0.AddSeconds(5)).Allowed);
        var replay = rig.Verifier.Verify(env, T0.AddSeconds(6));
        Assert.False(replay.Allowed);
        Assert.Contains("replay", replay.Reason);
    }

    [Fact]
    public void RMM03_KeyId_IsBoundToKeyMaterial()
    {
        var a = NewIdentity(); var b = NewIdentity();
        Assert.NotEqual(CustomerCommandKeyRing.KeyIdFor(a.PublicKey), CustomerCommandKeyRing.KeyIdFor(b.PublicKey));
        Assert.Equal(CustomerCommandKeyRing.KeyIdFor(a.PublicKey), new SignedCommandSigner(a).KeyId);
    }

    [Fact]
    public void RMM03_Rotation_OldKeyVerifiesDuringGrace_ThenRefuses()
    {
        var oldKey = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(oldKey.PublicKey);
        var oldSigner = new SignedCommandSigner(oldKey);
        var verifier = new SignedCommandVerifier(ring);

        var newKey = NewIdentity();
        ring.Rotate(newKey.PublicKey, T0, TimeSpan.FromHours(1));
        var newSigner = new SignedCommandSigner(newKey);

        // During grace: both keys verify (in-flight commands survive rotation).
        var fromOld = oldSigner.Sign(SignedCommandClasses.ShellExec, Bytes("old"), T0.AddMinutes(30), TimeSpan.FromMinutes(5));
        Assert.True(verifier.Verify(fromOld, T0.AddMinutes(31)).Allowed);
        var fromNew = newSigner.Sign(SignedCommandClasses.ShellExec, Bytes("new"), T0.AddMinutes(30), TimeSpan.FromMinutes(5));
        Assert.True(verifier.Verify(fromNew, T0.AddMinutes(31)).Allowed);

        // After grace: the retired key verifies NOTHING.
        var lateOld = oldSigner.Sign(SignedCommandClasses.ShellExec, Bytes("old-late"), T0.AddMinutes(30), TimeSpan.FromHours(3));
        var v = verifier.Verify(lateOld, T0.AddHours(2));
        Assert.False(v.Allowed);
        Assert.Contains("retired", v.Reason);
    }

    [Fact]
    public void RMM03_Gate_RefusalsAndAcceptances_AreChainedAuditEvents()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Gate.Authorize(env, T0.AddSeconds(5)).Allowed);
        var tampered = env with { PayloadBase64 = Convert.ToBase64String(Bytes("evil")) };
        Assert.False(rig.Gate.Authorize(tampered, T0.AddSeconds(6)).Allowed);
        Assert.False(rig.Gate.Authorize(null, T0.AddSeconds(7)).Allowed);
        var kinds = rig.Audit.Entries.Select(e => e.Kind).ToList();
        Assert.Contains("signed_command_accepted", kinds);
        Assert.Equal(2, kinds.Count(k => k == "signed_command_refused"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- wiring: shell path -------------------------------------

    private static ToolExecutionContext Ctx() =>
        new(TestUtil.BarePairing(Scopes.All), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public async Task RMM03_ShellPath_UnsignedRefused_WhenGateWired()
    {
        var rig = NewRig();
        var runner = new FakeRunner();
        var module = new ShellExecSystemModule(runner, rig.Gate);
        var result = await module.ExecuteAsync(Args("""{"command":"echo hi"}"""), Ctx(), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Equal("signed_command_refused", result.ErrorClass);
        Assert.Empty(runner.Calls); // nothing executed
    }

    [Fact]
    public async Task RMM03_ShellPath_ExecutesTheSignedPayload_NotTheUnsignedArgument()
    {
        var rig = NewRig();
        var runner = new FakeRunner();
        var module = new ShellExecSystemModule(runner, rig.Gate);
        // The gate verifies against wall-clock now; sign with UtcNow.
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo signed-truth"),
            DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args = JsonSerializer.Serialize(new { command = "echo unsigned-lie", signed_command = env.ToJson() });
        var result = await module.ExecuteAsync(Args(args), Ctx(), CancellationToken.None);
        Assert.True(result.Ok, result.Text);
        Assert.Single(runner.Calls);
        Assert.Contains("echo signed-truth", runner.Calls[0].Args);
        Assert.DoesNotContain("unsigned-lie", runner.Calls[0].Args);
    }

    [Fact]
    public async Task RMM03_ShellPath_NoGate_KeepsLegacyPosture()
    {
        var runner = new FakeRunner();
        var module = new ShellExecSystemModule(runner); // no customer key configured
        var result = await module.ExecuteAsync(Args("""{"command":"echo legacy"}"""), Ctx(), CancellationToken.None);
        Assert.True(result.Ok, result.Text);
        Assert.Single(runner.Calls);
    }

    // ---- wiring: session initiation ------------------------------

    [Fact]
    public async Task RMM03_SessionStart_RequiresSignedInitiation_WhenGateWired()
    {
        var rig = NewRig();
        var module = new SessionStartModule(new SessionManager(), new DeskGuest.Core.CoreState(), rig.Gate);
        var ctx = Ctx();
        // Unsigned: refused, no session.
        var unsigned = await module.ExecuteAsync(Args("""{}"""), ctx, CancellationToken.None);
        Assert.False(unsigned.Ok);
        Assert.Equal("signed_command_refused", unsigned.ErrorClass);
        // Signed for THIS pairing: starts.
        var env = rig.Signer.Sign(SignedCommandClasses.SessionInitiation,
            Bytes($"session_start|{ctx.Pairing.Id}"), DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args = JsonSerializer.Serialize(new { signed_command = env.ToJson() });
        var signed = await module.ExecuteAsync(Args(args), ctx, CancellationToken.None);
        Assert.True(signed.Ok, signed.Text);
    }

    [Fact]
    public async Task RMM03_SessionStart_EnvelopeForAnotherPairing_Refused()
    {
        var rig = NewRig();
        var module = new SessionStartModule(new SessionManager(), new DeskGuest.Core.CoreState(), rig.Gate);
        var env = rig.Signer.Sign(SignedCommandClasses.SessionInitiation,
            Bytes("session_start|some-other-pairing"), DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args = JsonSerializer.Serialize(new { signed_command = env.ToJson() });
        var result = await module.ExecuteAsync(Args(args), Ctx(), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Contains("does not name this pairing", result.Text);
    }

    // ---- wiring: update staging -----------------------------------

    private static byte[] TinyZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("payload.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("update payload");
        }
        return ms.ToArray();
    }

    // D38 F8 payload shape: version + package travel INSIDE the
    // signed payload as JSON. (Amended 2026-11-21 by the D38 fix
    // lane: this test previously signed the raw package and passed
    // version = "9.9.9" as an UNSIGNED argument, asserting the
    // staged version came from it — that was the finding's
    // baked-in defect, not a contract.)
    public static byte[] StageSignedPayload(byte[] pkg, string version) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            version,
            package_base64 = Convert.ToBase64String(pkg),
        }));

    [Fact]
    public async Task RMM03_UpdateStageSigned_VerifiesCustomerSignatureBeforeStaging()
    {
        var rig = NewRig();
        using var rsa = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(TestUtil.TempDir(), rsa, _ => Task.FromResult(true));
        var module = new AgentUpdateModule(updates, rig.Gate);
        var pkg = TinyZip();
        var env = rig.Signer.Sign(SignedCommandClasses.UpdateStaging,
            StageSignedPayload(pkg, "9.9.9"), DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args = JsonSerializer.Serialize(new
        {
            action = "stage_signed",
            signed_command = env.ToJson(),
            signature_base64 = Convert.ToBase64String(rsa.Sign(pkg)),
            // An unsigned version argument that DISAGREES with the
            // signed payload must be ignored (D38 F8):
            version = "0.0.1-unsigned-lie",
        });
        var result = await module.ExecuteAsync(Args(args), Ctx(), CancellationToken.None);
        Assert.True(result.Ok, result.Text);
        Assert.Equal("9.9.9", updates.Status().StagedVersion);
    }

    [Fact]
    public async Task RMM03_UpdateStageSigned_UnsignedOrForged_Refused_NothingStaged()
    {
        var rig = NewRig();
        using var rsa = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(TestUtil.TempDir(), rsa, _ => Task.FromResult(true));
        var module = new AgentUpdateModule(updates, rig.Gate);
        var pkg = TinyZip();
        // A perfectly product-signed package with NO customer envelope:
        var args = JsonSerializer.Serialize(new
        {
            action = "stage_signed",
            signature_base64 = Convert.ToBase64String(rsa.Sign(pkg)),
            version = "9.9.9",
        });
        var result = await module.ExecuteAsync(Args(args), Ctx(), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Equal("signed_command_refused", result.ErrorClass);
        Assert.Null(updates.Status().StagedVersion);
        // And with no gate wired at all, stage_signed refuses outright.
        var bareModule = new AgentUpdateModule(updates);
        var env = rig.Signer.Sign(SignedCommandClasses.UpdateStaging,
            StageSignedPayload(pkg, "9.9.9"), DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args2 = JsonSerializer.Serialize(new
        {
            action = "stage_signed", signed_command = env.ToJson(),
            signature_base64 = Convert.ToBase64String(rsa.Sign(pkg)), version = "9.9.9",
        });
        var result2 = await bareModule.ExecuteAsync(Args(args2), Ctx(), CancellationToken.None);
        Assert.False(result2.Ok);
        Assert.Null(updates.Status().StagedVersion);
    }
}
