using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Security;

namespace Acp.Tests;

public class Ed25519RfcVectorTests
{
    // RFC 8032 §7.1 TEST 1 — verified against the RFC text and the
    // Android implementation's vector-tested test file
    // (agent-control-app/android/tests/AdbCryptoTest.kt).
    private static readonly byte[] Test1Seed = Convert.FromHexString(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    private static readonly byte[] Test1Public = Convert.FromHexString(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static readonly byte[] Test1Signature = Convert.FromHexString(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    // RFC 8032 §7.1 TEST 2 — fetched from the RFC text (the task
    // brief's transcription of this vector was garbled: the real
    // message is the single byte 0x72 and the signature is below).
    private static readonly byte[] Test2Seed = Convert.FromHexString(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    private static readonly byte[] Test2Public = Convert.FromHexString(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    private static readonly byte[] Test2Message = Convert.FromHexString("72");
    private static readonly byte[] Test2Signature = Convert.FromHexString(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    [Fact]
    public void Test1_PublicKeyDerivation_MatchesRfc()
    {
        Assert.Equal(Test1Public, Ed25519.DerivePublicKey(Test1Seed));
    }

    [Fact]
    public void Test1_SignEmptyMessage_MatchesRfc_AndVerifies()
    {
        var sig = Ed25519.Sign(Test1Seed, Array.Empty<byte>());
        Assert.Equal(Test1Signature, sig);
        Assert.True(Ed25519.Verify(Test1Public, Array.Empty<byte>(), Test1Signature));
    }

    [Fact]
    public void Test2_PublicKeyDerivation_MatchesRfc()
    {
        Assert.Equal(Test2Public, Ed25519.DerivePublicKey(Test2Seed));
    }

    [Fact]
    public void Test2_Sign_MatchesRfc_AndVerifies()
    {
        var sig = Ed25519.Sign(Test2Seed, Test2Message);
        Assert.Equal(Test2Signature, sig);
        Assert.True(Ed25519.Verify(Test2Public, Test2Message, Test2Signature));
    }
}

public class DeviceIdentityTests
{
    [Fact]
    public void DeviceId_IsSha256Fingerprint_AndStable()
    {
        var protector = new DevOnlyPassThroughProtector();
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var a = new DeviceIdentity(protector, seed);
        var b = new DeviceIdentity(protector, seed);
        Assert.Equal(a.DeviceId, b.DeviceId);
        Assert.Equal(a.PublicKey, b.PublicKey);
        // Independently recomputed fingerprint.
        var expected = Convert.ToHexString(SHA256.HashData(a.PublicKey)).ToLowerInvariant();
        Assert.Equal(expected, a.DeviceId);
        Assert.Equal(64, a.DeviceId.Length);
        Assert.Equal(a.DeviceId, a.DeviceId.ToLowerInvariant());
    }

    [Fact]
    public void GeneratedIdentities_AreDistinct()
    {
        var protector = new DevOnlyPassThroughProtector();
        var a = new DeviceIdentity(protector);
        var b = new DeviceIdentity(protector);
        Assert.NotEqual(a.DeviceId, b.DeviceId);
    }

    [Fact]
    public void SignVerify_RoundTrip()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var message = Encoding.UTF8.GetBytes("hello enrollment");
        var sig = identity.Sign(message);
        Assert.Equal(64, sig.Length);
        Assert.True(Ed25519.Verify(identity.PublicKey, message, sig));
    }

    [Fact]
    public void Verify_TamperedMessage_Fails()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var sig = identity.Sign(Encoding.UTF8.GetBytes("original"));
        Assert.False(Ed25519.Verify(identity.PublicKey, Encoding.UTF8.GetBytes("tampered"), sig));
    }

    [Fact]
    public void Verify_TamperedSignature_Fails()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var message = Encoding.UTF8.GetBytes("msg");
        var sig = identity.Sign(message);
        var badR = sig.ToArray(); badR[0] ^= 0x01;
        Assert.False(Ed25519.Verify(identity.PublicKey, message, badR));
        var badS = sig.ToArray(); badS[40] ^= 0x01;
        Assert.False(Ed25519.Verify(identity.PublicKey, message, badS));
    }

    [Fact]
    public void Verify_WrongPublicKey_Fails()
    {
        var a = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var b = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var message = Encoding.UTF8.GetBytes("msg");
        Assert.False(Ed25519.Verify(b.PublicKey, message, a.Sign(message)));
    }

    [Fact]
    public void Verify_MalformedInput_ReturnsFalse_NeverThrows()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var message = Encoding.UTF8.GetBytes("msg");
        var sig = identity.Sign(message);
        Assert.False(Ed25519.Verify(Array.Empty<byte>(), message, sig));
        Assert.False(Ed25519.Verify(new byte[31], message, sig));
        Assert.False(Ed25519.Verify(identity.PublicKey, message, Array.Empty<byte>()));
        Assert.False(Ed25519.Verify(identity.PublicKey, message, new byte[63]));
        Assert.False(Ed25519.Verify(identity.PublicKey, message, new byte[65]));
        Assert.False(Ed25519.Verify(new byte[32], message, sig)); // zero public key encoding
        // Non-canonical S (all 0xFF) must be rejected, not crash.
        var badS = sig.ToArray();
        Array.Fill(badS, (byte)0xFF, 32, 32);
        Assert.False(Ed25519.Verify(identity.PublicKey, message, badS));
        // R that is not a valid point encoding.
        var badR = sig.ToArray();
        Array.Fill(badR, (byte)0xFF, 0, 32);
        Assert.False(Ed25519.Verify(identity.PublicKey, message, badR));
    }

    [Fact]
    public void ProtectedSeed_RoundTrip_RestoresSameIdentity()
    {
        var protector = new DevOnlyPassThroughProtector();
        var identity = new DeviceIdentity(protector);
        var restored = DeviceIdentity.ImportProtectedSeed(protector, identity.ExportProtectedSeed());
        Assert.Equal(identity.DeviceId, restored.DeviceId);
        Assert.Equal(identity.PublicKey, restored.PublicKey);
        var message = Encoding.UTF8.GetBytes("still me");
        Assert.True(Ed25519.Verify(identity.PublicKey, message, restored.Sign(message)));
    }

    [Fact]
    public void ExportProtectedSeed_ContainsNoRawSeed()
    {
        var protector = new DevOnlyPassThroughProtector();
        var seed = Convert.FromHexString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        var identity = new DeviceIdentity(protector, seed);
        var exported = identity.ExportProtectedSeed();
        Assert.DoesNotContain(Convert.ToHexString(seed), exported, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(seed), exported);
    }

    [Fact]
    public void TryImportProtectedSeed_Malformed_ReturnsFalse()
    {
        var protector = new DevOnlyPassThroughProtector();
        Assert.False(DeviceIdentity.TryImportProtectedSeed(protector, "!!!not-base64!!!", out var id));
        Assert.Null(id);
        Assert.False(DeviceIdentity.TryImportProtectedSeed(protector, null, out _));
        Assert.False(DeviceIdentity.TryImportProtectedSeed(protector, "", out _));
    }

    [Fact]
    public void KeyPair_Generate_ProducesVerifiableSignature()
    {
        var (seed, publicKey) = Ed25519.GenerateKeyPair();
        Assert.Equal(32, seed.Length);
        Assert.Equal(publicKey, Ed25519.DerivePublicKey(seed));
        var message = Encoding.UTF8.GetBytes("kp");
        Assert.True(Ed25519.Verify(publicKey, message, Ed25519.Sign(seed, message)));
    }
}
