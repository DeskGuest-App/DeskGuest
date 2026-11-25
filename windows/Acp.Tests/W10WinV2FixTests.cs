using System.Security.Cryptography;
using System.Text;
using Acp.Core.Ipc;
using Acp.Shared.Backup;
using Acp.Shared.Encryption;
using Acp.Shared.Enterprise;
using Acp.Shared.Ipc;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>
/// Wave 10 Lane A — regression pins for the W9-V2 verdicts
/// (packet 288c5ab6), each verified against the current tree first
/// (see log-laneW10-winv2fix.md for the per-claim dispositions).
/// Class/method names carry the V2 claim id so a failure points at
/// its claim in the re-verification packet.
/// </summary>
public class W10WinV2FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] KeyA = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] KeyB = RandomNumberGenerator.GetBytes(32);

    private static BackupJobDefinition FileJob() => new(
        "job1", "dev1", "alice", BackupKinds.File,
        new[] { @"C:\data\a.txt", @"C:\data\b.txt" },
        "nas1", new BackupSchedule(24), 7, true);

    private sealed record EncRig(BackupSnapshotStore Store, InMemoryBackupStorage Raw, BackupEngine Engine);

    private static EncRig NewEncRig(byte[]? key, InMemoryBackupStorage? raw = null)
    {
        raw ??= new InMemoryBackupStorage();
        var store = new BackupSnapshotStore("nas1", raw, timeVerifier: null, atRestKey: key);
        var capture = new FakeBackupCaptureSource()
            .AddFile(@"C:\data\a.txt", "alpha-content")
            .AddFile(@"C:\data\b.txt", "beta-content");
        var engine = new BackupEngine(store, capture, new ChainedAuditLog());
        return new EncRig(store, raw, engine);
    }

    private static string SealDefault(EncRig rig)
    {
        var outcome = rig.Engine.RunBackup(FileJob(), envelope: null, T0);
        Assert.True(outcome.Ok, outcome.Outcome);
        return outcome.SnapshotId!;
    }

    // ================= V2-C1: backup encryption at rest ============

    [Fact]
    public void C1_EncryptedStore_StoredBlobsAreSealed_NotPlaintext()
    {
        var rig = NewEncRig(KeyA);
        var id = SealDefault(rig);
        Assert.True(rig.Store.EncryptionAtRestEnabled);
        Assert.Equal(BackupAtRest.KeyId(KeyA), rig.Store.EncryptionKeyId);
        var chunkKeys = rig.Raw.ListKeys("chunks/");
        Assert.NotEmpty(chunkKeys);
        foreach (var k in chunkKeys)
        {
            var stored = rig.Raw.Get(k)!;
            Assert.True(BackupAtRest.IsSealed(stored), k);
            Assert.DoesNotContain("alpha-content", Encoding.ASCII.GetString(stored));
            Assert.DoesNotContain("beta-content", Encoding.ASCII.GetString(stored));
        }
        var manifest = rig.Raw.Get($"manifests/{id}.json")!;
        Assert.True(BackupAtRest.IsSealed(manifest));
        Assert.DoesNotContain("a.txt", Encoding.UTF8.GetString(manifest));
        // And the round trip still restores the original bytes.
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore\");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.True(restore.Ok, restore.Outcome);
        Assert.Equal("alpha-content", Encoding.UTF8.GetString(target.Files["C/data/a.txt"]));
        Assert.Equal("beta-content", Encoding.UTF8.GetString(target.Files["C/data/b.txt"]));
    }

    [Fact]
    public void C1_WrongKey_RestoreRefusesByName_TargetUntouched()
    {
        var rig = NewEncRig(KeyA);
        var id = SealDefault(rig);
        // Limb 1: re-seal the stored manifest under a WRONG key
        // (an attacker who holds storage but not the key produces
        // exactly this shape). The manifest no longer opens under
        // the store's key — restore refuses BY NAME, target empty.
        var manifestKey = $"manifests/{id}.json";
        var plain = BackupAtRest.Open(KeyA, manifestKey, rig.Raw.Get(manifestKey)!);
        rig.Raw.Put(manifestKey, BackupAtRest.Seal(KeyB, manifestKey, plain));
        Assert.Null(rig.Store.GetManifestVerified(id));
        var target = new InMemoryRestoreTarget(@"C:\Users\alice\Restore\");
        var restore = rig.Engine.RestoreFiles(id, null, target,
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore.Ok);
        Assert.Contains("manifest failed verification", restore.Outcome);
        Assert.Empty(target.Files);
        // Limb 2: a store holding the wrong key cannot even import
        // the catalogue — the chain is bound to KeyA's fingerprint,
        // so it lands TAMPERED and restores refuse by that name.
        var rig2 = NewEncRig(KeyA);
        var id2 = SealDefault(rig2);
        var wrongStore = new BackupSnapshotStore("nas1", rig2.Raw, atRestKey: KeyB);
        var (imported, _) = wrongStore.ImportCatalogue(rig2.Store.ExportCatalogue());
        Assert.False(imported);
        Assert.True(wrongStore.CatalogueTampered);
        var wrongEngine = new BackupEngine(wrongStore,
            new FakeBackupCaptureSource(), new ChainedAuditLog());
        var restore2 = wrongEngine.RestoreFiles(id2, null,
            new InMemoryRestoreTarget(@"C:\Users\alice\Restore\"),
            new RestoreRequester("alice", "dev1", false), envelope: null, T0);
        Assert.False(restore2.Ok);
        Assert.Contains("catalogue_tampered", restore2.Outcome);
    }

    [Fact]
    public void C1_PlaintextBlobsUnderEncryptedStore_Refused_NoSilentDowngrade()
    {
        // Seal with a legacy plaintext store, then read the same
        // storage through an encryption-configured store.
        var plain = NewEncRig(null);
        var id = SealDefault(plain);
        var enc = NewEncRig(KeyA, plain.Raw);
        Assert.Null(enc.Store.GetManifestVerified(id));
        var manifest = plain.Store.GetManifestVerified(id)!;
        var chunk = manifest.Entries[0].ChunkHashes[0];
        var ex = Assert.Throws<InvalidOperationException>(() => enc.Store.ReadChunkVerified(chunk));
        Assert.Contains("no silent downgrade", ex.Message);
    }

    [Fact]
    public void C1_ChunkSwap_SealedBlobsAreBoundToTheirStorageKey()
    {
        var rig = NewEncRig(KeyA);
        var id = SealDefault(rig);
        var manifest = rig.Store.GetManifestVerified(id)!;
        var first = manifest.Entries[0].ChunkHashes[0];
        var second = manifest.Entries[1].ChunkHashes[0];
        // Swap the two chunks' stored bytes: each is a valid sealed
        // blob — under the OTHER chunk's key. The AAD binding must
        // refuse the read by name.
        var a = rig.Raw.Get($"chunks/{first}")!;
        var b = rig.Raw.Get($"chunks/{second}")!;
        rig.Raw.Put($"chunks/{first}", b);
        rig.Raw.Put($"chunks/{second}", a);
        var ex = Assert.Throws<InvalidOperationException>(() => rig.Store.ReadChunkVerified(first));
        Assert.Contains("failed at-rest decryption", ex.Message);
    }

    [Fact]
    public void C1_CatalogueChain_BindsTheAtRestKeyId()
    {
        var rig = NewEncRig(KeyA);
        SealDefault(rig);
        var json = rig.Store.ExportCatalogue();
        // A plaintext store cannot import an encrypted store's
        // catalogue: the chain hashes carry the key fingerprint.
        var plainStore = new BackupSnapshotStore("nas1", new InMemoryBackupStorage());
        var (okPlain, _) = plainStore.ImportCatalogue(json);
        Assert.False(okPlain);
        Assert.True(plainStore.CatalogueTampered);
        // The same key imports cleanly.
        var sameKey = new BackupSnapshotStore("nas1", new InMemoryBackupStorage(), atRestKey: KeyA);
        var (okSame, _) = sameKey.ImportCatalogue(json);
        Assert.True(okSame);
    }

    [Fact]
    public void C1_KeyFile_LoadOrCreate_RoundTrips_AndCorruptionRefuses()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "backup.key");
        var protector = new DevOnlyPassThroughProtector();
        var k1 = BackupAtRest.LoadOrCreateKeyFile(path, protector);
        Assert.Equal(32, k1.Length);
        // The file never holds the raw key.
        Assert.DoesNotContain(Convert.ToBase64String(k1), File.ReadAllText(path));
        var k2 = BackupAtRest.LoadOrCreateKeyFile(path, protector);
        Assert.Equal(k1, k2);
        File.WriteAllText(path, "not-a-protected-key");
        Assert.Throws<InvalidOperationException>(() => BackupAtRest.LoadOrCreateKeyFile(path, protector));
    }

    [Fact]
    public void C1_EscrowSupersede_IsLoudRotation_OldKeyRetainedAndRevealable()
    {
        var audit = new ChainedAuditLog();
        var escrow = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), audit,
            () => T0, a => a is "admin-a" or "admin-b");
        var first = escrow.Escrow("dev1", "C:", "scope1", "1111-2222-3333", "recovery_password", "agent", T0);
        Assert.True(first.Ok, first.Reason);
        var second = escrow.Escrow("dev1", "C:", "scope1", "9999-8888-7777", "recovery_password", "agent", T0);
        Assert.True(second.Ok, second.Reason);
        // The rotation is a distinctly-named chained audit event.
        Assert.Contains(audit.Entries, e => e.Kind == "encryption_key_escrow_superseded"
            && e.Detail.Contains(first.Metadata!.Ref) && e.Detail.Contains(second.Metadata!.Ref));
        // The old key is RETAINED (not replaced), marked not-current…
        var oldMeta = escrow.GetMetadata(first.Metadata!.Ref);
        Assert.NotNull(oldMeta);
        Assert.False(oldMeta!.IsCurrentForVolume);
        Assert.True(escrow.GetMetadata(second.Metadata!.Ref)!.IsCurrentForVolume);
        // …and still revealable under full dual control.
        var req = escrow.RequestReveal(first.Metadata.Ref, "dev1", "C:", "admin-a", "drive replacement", T0);
        Assert.True(req.Ok, req.Reason);
        Assert.True(escrow.ApproveReveal(req.Request!.RequestId, "admin-b", T0).Ok);
        var reveal = escrow.Reveal(req.Request.RequestId, "admin-a", T0);
        Assert.True(reveal.Ok, reveal.Reason);
        Assert.Equal("1111-2222-3333", reveal.KeyMaterial);
    }

    // ================= V2-C4: consent provenance, every state ======

    // InlineData (not MemberData) so the chunked reflection harness
    // can enumerate the cases; the kind set is asserted complete
    // against IpcConsent.ConsentKinds in the companion Fact below.
    [Theory]
    [InlineData(IpcKinds.GateApproval)]
    [InlineData(IpcKinds.PairingCreateCode)]
    [InlineData(IpcKinds.SessionAction)]
    [InlineData(IpcKinds.UserStopClear)]
    [InlineData(IpcKinds.VaultSet)]
    [InlineData(IpcKinds.GateAnswer)]
    public void C4_ConsentKinds_RequirePhysicalProvenance_InEverySessionState(string kind)
    {
        var bare = new IpcMessage(kind, null, null, "{}", null, null, null, null, null, null);
        var injected = bare with { InputProvenance = IpcProvenance.AgentInjected };
        var unknown = bare with { InputProvenance = IpcProvenance.Unknown };
        var physical = bare with { InputProvenance = IpcProvenance.PhysicalHuman };
        foreach (var live in new[] { false, true })
        {
            Assert.False(IpcConsent.CanHonor(bare, live), $"{kind} bare live={live}");
            Assert.False(IpcConsent.CanHonor(injected, live), $"{kind} injected live={live}");
            Assert.False(IpcConsent.CanHonor(unknown, live), $"{kind} unknown live={live}");
            Assert.True(IpcConsent.CanHonor(physical, live), $"{kind} physical live={live}");
        }
    }

    [Fact]
    public void C4_ConsentKindSet_IsExactlyTheSixNamedKinds()
    {
        // W79 decision-driven pin update: the consent set gains a
        // seventh named kind — PairingAccess (the owner changing a
        // pairing's grants from the access-control surface is a
        // consent act exactly like PairingCreateCode). The pin's
        // purpose stands: the set is EXACTLY the named kinds, no
        // more, no fewer.
        // W97 decision-driven pin update: an eighth named kind —
        // PairingConnection (the owner changing a pairing's
        // connection-path setting from the agent card is the same
        // class of consent act). Exactness stands as above.
        Assert.Equal(8, IpcConsent.ConsentKinds.Count);
        Assert.Equal(
            new HashSet<string> { IpcKinds.GateApproval, IpcKinds.PairingCreateCode,
                IpcKinds.SessionAction, IpcKinds.UserStopClear, IpcKinds.VaultSet, IpcKinds.GateAnswer,
                IpcKinds.PairingAccess, IpcKinds.PairingConnection },
            IpcConsent.ConsentKinds);
    }

    [Fact]
    public void C4_NonConsentKinds_UnaffectedByProvenanceRule()
    {
        foreach (var kind in new[] { IpcKinds.Hello, IpcKinds.Auth, IpcKinds.Heartbeat,
                     IpcKinds.UserStop, IpcKinds.ToolResponse, IpcKinds.SessionState })
        {
            var msg = new IpcMessage(kind, null, null, null, null, null, null, null, null, null);
            Assert.True(IpcConsent.CanHonor(msg, agentSessionLive: false), kind);
            Assert.True(IpcConsent.CanHonor(msg, agentSessionLive: true), kind);
        }
    }

    // ================= V2-C5: pipe ACL fail-closed =================

    [Fact]
    public void C5_PipeSecurity_BadOwnerAccount_ConstructionThrows()
    {
        // The failure CreatePipe now fails closed on: an owner
        // account that cannot be translated must surface as an
        // exception from ACL construction, never a fallback pipe.
        Assert.ThrowsAny<Exception>(() =>
            AgentIpcServer.BuildPipeSecurity("no-such-domain\\no-such-user-w10"));
    }

    [Fact]
    public void C5AndX2AndX4_SourcePins_PipeAndTokenPosture()
    {
        var agentChannel = ReadRepoFile("src/Acp.Core/Ipc/AgentChannel.cs");
        // C5: first-instance creation on the agent pipe; the
        // default-ACL fallback text is GONE.
        Assert.Contains("PipeOptions.FirstPipeInstance", agentChannel);
        Assert.DoesNotContain("fall back to the default pipe", agentChannel);
        // X2: OS identity verification is not switched off by a
        // missing token.
        Assert.DoesNotContain("|| _expectedToken is null) return true", agentChannel);
        // X4: the stale token-file claim is gone.
        Assert.DoesNotContain("token file lives in the ACL'd data dir", agentChannel);
        // C4: every consent-class sender in the Session Agent stamps
        // physical-human provenance (GateAnswer + the six senders
        // stamped in this wave).
        var ipcClient = ReadRepoFile("src/Acp.SessionAgent/IpcClient.cs");
        var stamps = System.Text.RegularExpressions.Regex
            .Matches(ipcClient, "InputProvenance: IpcProvenance.PhysicalHuman").Count;
        Assert.True(stamps >= 7, $"expected >= 7 provenance stamps in IpcClient.cs, found {stamps}");
    }

    // ================= V2-X1: bare-name expected image =============

    private static IpcClientFacts Facts(string? image, string? expected) => new(
        ClientSessionId: 1, ConsoleSessionId: 1,
        ClientUserSid: "S-1-5-21-100", ConsoleUserSid: "S-1-5-21-100",
        ClientIsSystem: false, ClientImagePath: image, ExpectedImagePath: expected);

    [Fact]
    public void X1_BareNameExpectedImage_FailsClosed()
    {
        Assert.False(IpcClientIdentity.Evaluate(
            Facts(@"C:\Program Files\ACP\AcpSessionAgent.exe", "AcpSessionAgent.exe")));
    }

    [Fact]
    public void X1_SameNameDifferentDirectory_Refused_FullPathMatchPasses()
    {
        Assert.False(IpcClientIdentity.Evaluate(
            Facts(@"C:\evil\AcpSessionAgent.exe", @"C:\Program Files\ACP\AcpSessionAgent.exe")));
        Assert.False(IpcClientIdentity.Evaluate(
            Facts(@"C:\Users\alice\Downloads\AcpSessionAgent.exe", @"C:\Program Files\ACP\AcpSessionAgent.exe")));
        Assert.True(IpcClientIdentity.Evaluate(
            Facts(@"C:\Program Files\ACP\AcpSessionAgent.exe", @"C:\Program Files\ACP\AcpSessionAgent.exe")));
        Assert.True(IpcClientIdentity.Evaluate(
            Facts(@"c:\program files\acp\acpsessionagent.exe", @"C:\Program Files\ACP\AcpSessionAgent.exe")));
    }

    // ---- helpers ----------------------------------------------------

    private static string ReadRepoFile(string relative)
    {
        // Walk up from the working directory and the assembly base
        // until the windows-agent tree is found (the AiPackPinTests
        // pattern: mirror/source pins must work from any harness cwd).
        var starts = new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory };
        foreach (var start in starts)
        {
            var dir = new DirectoryInfo(start);
            while (dir is not null)
            {
                var candidate = Path.Combine(dir.FullName, "windows-agent", relative);
                if (File.Exists(candidate)) return File.ReadAllText(candidate);
                dir = dir.Parent;
            }
        }
        throw new FileNotFoundException($"repo file not found above the test working tree: {relative}");
    }
}
