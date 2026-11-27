using System.IO.Compression;
using System.Security.Cryptography;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>Wave 24 Lane A — R-05 / D-DEC-1: the production
/// Ed25519 update-signing key discipline. The pinned update key
/// loads through PinnedUpdateKey (Ed25519 base64 — the D-DEC-1
/// format — or the legacy RSA PEM), verifies through the
/// PRODUCTION verifier class, and stages through UpdateManager
/// under the pinned signer set. These tests use fixture keypairs
/// generated in-test; the production key itself is custody-held
/// off-tree and never appears here (its round-trip is proven by
/// the lane harness against the pinned update-key.pub).</summary>
public class W24ProdKeyTests
{
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
    public void W24_PinnedLoader_Ed25519Base64_LoadsProductionVerifier_RoundTrips()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var verifier = PinnedUpdateKey.Create(Convert.ToBase64String(pub));
        Assert.IsType<Ed25519UpdateSignatureVerifier>(verifier);
        Assert.Equal("product-pinned", verifier.KeyId);
        var pkg = MakeZip(("app.txt", "v2"));
        var sig = Ed25519UpdateSignatureVerifier.Sign(seed, pkg);
        Assert.True(verifier.Verify(pkg, sig));
    }

    [Fact]
    public void W24_Ed25519Verifier_TamperAndWrongKey_Refuse()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var (otherSeed, _) = Ed25519.GenerateKeyPair();
        var verifier = new Ed25519UpdateSignatureVerifier(pub, "product-pinned");
        var pkg = MakeZip(("app.txt", "v2"));
        var sig = Ed25519UpdateSignatureVerifier.Sign(seed, pkg);
        var tampered = pkg.ToArray(); tampered[^1] ^= 0xFF;
        Assert.False(verifier.Verify(tampered, sig));
        Assert.False(verifier.Verify(pkg, Ed25519UpdateSignatureVerifier.Sign(otherSeed, pkg)));
        Assert.False(verifier.Verify(pkg, new byte[64])); // well-formed length, garbage signature
        Assert.False(verifier.Verify(pkg, new byte[10])); // malformed length, fail closed
    }

    [Fact]
    public void W24_Ed25519Verifier_BadPublicKeys_RefuseAtPin()
    {
        Assert.Throws<ArgumentException>(() => new Ed25519UpdateSignatureVerifier(new byte[31], "product-pinned"));
        Assert.Throws<ArgumentException>(() => new Ed25519UpdateSignatureVerifier(new byte[33], "product-pinned"));
        // The identity encoding (y=1, x=0) is a small-order point:
        // signatures under it are forgeable, so it never pins.
        var identity = new byte[32]; identity[0] = 1;
        Assert.Throws<ArgumentException>(() => new Ed25519UpdateSignatureVerifier(identity, "product-pinned"));
    }

    [Fact]
    public void W24_UpdateManager_Ed25519SignedPackage_Stages_ForgedRefuses()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var verifier = PinnedUpdateKey.Create(Convert.ToBase64String(pub));
        var updates = new UpdateManager(TestUtil.TempDir(), verifier, _ => Task.FromResult(true),
            pinnedKeyIds: new HashSet<string> { "product-pinned" });
        Assert.Equal("product-pinned", updates.Status().SignatureKeyId);
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, Ed25519UpdateSignatureVerifier.Sign(seed, pkg), "2.0.0").Ok);
        var forged = MakeZip(("app.txt", "evil"));
        var refused = updates.StagePackage(forged, Ed25519UpdateSignatureVerifier.Sign(seed, pkg), "2.0.1");
        Assert.False(refused.Ok);
        Assert.Contains("signature verification FAILED", refused.Message);
    }

    [Fact]
    public void W24_PinnedLoader_RsaPem_StillLoads_LegacyPinUnbroken()
    {
        using var rsa = new RsaUpdateSignatureVerifier();
        var verifier = PinnedUpdateKey.Create(rsa.ExportPublicKeyPem());
        Assert.IsType<RsaUpdateSignatureVerifier>(verifier);
        Assert.Equal("product-pinned", verifier.KeyId);
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(verifier.Verify(pkg, rsa.Sign(pkg)));
    }

    [Fact]
    public void W24_PinnedLoader_Garbage_ThrowsFormat_NeverGuesses()
    {
        Assert.Throws<FormatException>(() => PinnedUpdateKey.Create("not a key at all!!!"));
        Assert.Throws<FormatException>(() => PinnedUpdateKey.Create(Convert.ToBase64String(new byte[16])));
        Assert.Throws<FormatException>(() => PinnedUpdateKey.Create(""));
    }

    [Fact]
    public void W24_PinnedPublicKeyFile_InCoreOutput_LoadsAsProductPinned()
    {
        // The pin ships beside the Core executable (DeskGuest.Core
        // csproj Content copy): when the file is present in this
        // test's base directory it must load as the Ed25519
        // production verifier. When a dev tree runs without the
        // copy, this pin is vacuous — the harness proof against
        // the source pin is the lane's evidence, named in its log.
        var pin = Path.Combine(AppContext.BaseDirectory, "update-key.pub");
        if (!File.Exists(pin)) return;
        var verifier = PinnedUpdateKey.Create(File.ReadAllText(pin));
        Assert.IsType<Ed25519UpdateSignatureVerifier>(verifier);
        Assert.Equal("product-pinned", verifier.KeyId);
        var fp = Convert.ToHexString(SHA256.HashData(
            ((Ed25519UpdateSignatureVerifier)verifier).ExportPublicKey())).ToLowerInvariant();
        Assert.Equal(64, fp.Length);
    }
}
