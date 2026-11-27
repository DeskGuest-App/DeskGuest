using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

public class FileAndUpdateTests
{
    private static ToolExecutionContext Ctx() =>
        new(TestUtil.BarePairing(DeskGuest.Shared.Security.Scopes.All), TestUtil.Session(),
            TestUtil.State(), new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void FileScope_InsideRoot_Resolves()
    {
        var root = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        Assert.NotNull(scope.ResolveInScope(Path.Combine(root, "a.txt")));
    }

    [Fact]
    public void FileScope_EscapeAttempts_Refused()
    {
        var root = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        Assert.Null(scope.ResolveInScope(Path.Combine(root, "..", "outside.txt")));
        Assert.Null(scope.ResolveInScope("/etc/passwd"));
        Assert.Null(scope.ResolveInScope(root + "-sibling/evil.txt"));
    }

    [Fact]
    public async Task FileWriteRead_RoundTrips_ThroughModules()
    {
        var root = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        var path = Path.Combine(root, "note.txt");
        var write = await new FileWriteModule(scope).ExecuteAsync(
            Args(JsonSerializer.Serialize(new { path, content = "hello deskguest" })), Ctx(), default);
        Assert.True(write.Ok, write.Text);
        var read = await new FileReadModule(scope).ExecuteAsync(
            Args(JsonSerializer.Serialize(new { path })), Ctx(), default);
        Assert.True(read.Ok);
        Assert.Contains("hello deskguest", read.Text);
    }

    [Fact]
    public async Task Transfer_HashMismatch_Rejected_NothingWritten()
    {
        var root = TestUtil.TempDir();
        var dataDir = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        var module = new FileTransferModule(scope, dataDir);
        var dest = Path.Combine(root, "up.bin");
        var wrongHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("different content")));
        var begin = await module.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "begin", destination = dest, sha256 = wrongHash })), Ctx(), default);
        Assert.True(begin.Ok, begin.Text);
        var id = JsonDocument.Parse(begin.Text!).RootElement.GetProperty("transfer_id").GetString();
        var chunk = await module.ExecuteAsync(Args(JsonSerializer.Serialize(new
        {
            action = "chunk", transfer_id = id,
            data_base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("actual content"))
        })), Ctx(), default);
        Assert.True(chunk.Ok, chunk.Text);
        var commit = await module.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "commit", transfer_id = id })), Ctx(), default);
        Assert.False(commit.Ok);
        Assert.Equal("hash_mismatch", commit.ErrorClass);
        Assert.False(File.Exists(dest));
    }

    [Fact]
    public async Task Transfer_CorrectHash_Commits()
    {
        var root = TestUtil.TempDir();
        var dataDir = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        var module = new FileTransferModule(scope, dataDir);
        var dest = Path.Combine(root, "up.bin");
        var payload = Encoding.UTF8.GetBytes("payload bytes");
        var hash = Convert.ToHexString(SHA256.HashData(payload));
        var begin = await module.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "begin", destination = dest, sha256 = hash })), Ctx(), default);
        var id = JsonDocument.Parse(begin.Text!).RootElement.GetProperty("transfer_id").GetString();
        await module.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "chunk", transfer_id = id, data_base64 = Convert.ToBase64String(payload) })), Ctx(), default);
        var commit = await module.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "commit", transfer_id = id })), Ctx(), default);
        Assert.True(commit.Ok, commit.Text);
        Assert.Equal(payload, await File.ReadAllBytesAsync(dest));
    }

    private static byte[] MakeZip(string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("app.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
        return ms.ToArray();
    }

    [Fact]
    public void Update_BadSignature_Refused_NothingExtracted()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        using var otherKey = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, otherKey, _ => Task.FromResult(true));
        var package = MakeZip("v2");
        var (ok, message) = updates.StagePackage(package, signer.Sign(package), "2.0.0");
        Assert.False(ok);
        Assert.Contains("signature", message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(updates.Status().StagedVersion);
    }

    [Fact]
    public async Task Update_HealthGateFailure_RollsBackAndQuarantines()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(false));
        var package = MakeZip("v2");
        var before = updates.Status();
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        var (ok, message) = await updates.ApplyStagedAsync(default);
        Assert.False(ok);
        Assert.Contains("health gate", message, StringComparison.OrdinalIgnoreCase);
        var after = updates.Status();
        Assert.Equal(before.ActiveSlot, after.ActiveSlot);
        Assert.Equal(before.ActiveVersion, after.ActiveVersion);
        Assert.Null(after.StagedVersion);
        Assert.True(Directory.Exists(Path.Combine(root, "quarantine")));
    }

    [Fact]
    public async Task Update_HealthyGate_FlipsActiveSlot()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(true));
        var package = MakeZip("v2-content");
        var before = updates.Status();
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        var (ok, _) = await updates.ApplyStagedAsync(default);
        Assert.True(ok);
        var after = updates.Status();
        Assert.NotEqual(before.ActiveSlot, after.ActiveSlot);
        Assert.Equal("2.0.0", after.ActiveVersion);
        Assert.Contains("v2-content", await File.ReadAllTextAsync(Path.Combine(updates.ActiveSlotDir, "app.txt")));
    }
}

public class UpdateHardeningTests
{
    [Fact]
    public async Task Update_CorruptPointer_DefaultsInsteadOfThrowing()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(true));
        await File.WriteAllTextAsync(Path.Combine(root, "active-slot.json"), "{torn write");
        var status = updates.Status(); // must not throw (M3)
        Assert.Equal(UpdateSlot.A, status.ActiveSlot);
        Assert.Equal(verifier.KeyId, status.SignatureKeyId); // M4: the key in force is named
    }

    [Fact]
    public async Task Update_TraversalVersion_QuarantineStaysInsideRoot()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(false));
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("app.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("vX");
        }
        var package = ms.ToArray();
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "../../evil").Ok);
        var (ok, _) = await updates.ApplyStagedAsync(default);
        Assert.False(ok);
        var quarantineRoot = Path.GetFullPath(Path.Combine(root, "quarantine"));
        Assert.True(Directory.Exists(quarantineRoot));
        Assert.False(Directory.Exists(Path.Combine(Path.GetDirectoryName(root)!, "evil")));
        // The real property: every quarantined slot lives INSIDE the
        // quarantine root — the traversal version became a flat filename.
        Assert.All(Directory.GetDirectories(quarantineRoot),
            d => Assert.StartsWith(quarantineRoot + Path.DirectorySeparatorChar, d));
    }
}
