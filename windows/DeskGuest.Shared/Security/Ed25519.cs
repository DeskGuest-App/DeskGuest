using System.Numerics;
using System.Security.Cryptography;

namespace DeskGuest.Shared.Security;

/// <summary>
/// Ed25519 per RFC 8032, implemented from the §5 reference formulas
/// over <see cref="BigInteger"/> — the same shape as the Android
/// implementation (agent-control-app Ed25519.kt), which is proven
/// against the RFC 8032 §7.1 test vectors. No native code, no external
/// dependencies: SHA-512 is the only platform primitive used.
///
/// Points are extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
/// T = XY/Z. Encoding/decoding follow RFC 8032: 32-byte little-endian
/// y with the sign of x in the top bit.
///
/// Verify is fail-closed and exception-free: bad lengths, undecodable
/// points, and non-canonical S all return false.
/// </summary>
public static class Ed25519
{
    private static readonly BigInteger P =
        (BigInteger.One << 255) - 19;

    /// <summary>The group order L = 2^252 + 27742317777372353535851937790883648493.</summary>
    public static readonly BigInteger L =
        (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    /// <summary>d = -121665/121666 mod p (computed, never transcribed).</summary>
    private static readonly BigInteger D =
        Mod(Mod(-121665) * ModInverse(121666));

    private static readonly BigInteger D2 = Mod(D * 2);

    /// <summary>sqrt(-1) mod p = 2^((p-1)/4) mod p, for point decoding.</summary>
    private static readonly BigInteger SqrtM1 =
        BigInteger.ModPow(2, (P - 1) / 4, P);

    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)
    {
        public BigInteger AffineX() => Mod(X * ModInverse(Z));
        public BigInteger AffineY() => Mod(Y * ModInverse(Z));
    }

    private static readonly Point Identity = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);

    private static readonly Point Base = Decode(
        Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666"))
        ?? throw new InvalidOperationException("base point encoding must decode");

    // ---- field helpers -------------------------------------------------

    private static BigInteger Mod(BigInteger a) => ((a % P) + P) % P;

    private static BigInteger ModInverse(BigInteger a) =>
        BigInteger.ModPow(Mod(a), P - 2, P); // p is prime

    private static BigInteger LittleEndianToInt(ReadOnlySpan<byte> bytes)
    {
        // BigInteger's span constructor is signed little-endian; append a
        // zero byte via the unsigned array constructor instead.
        var arr = bytes.ToArray();
        return new BigInteger(arr, isUnsigned: true, isBigEndian: false);
    }

    private static byte[] IntToLittleEndian(BigInteger value, int length)
    {
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        var outp = new byte[length];
        Array.Copy(raw, outp, Math.Min(raw.Length, length));
        return outp;
    }

    // ---- group operations (RFC 8032 reference formulas, a = -1) --------

    private static Point Add(Point p1, Point p2)
    {
        var a = Mod((p1.Y - p1.X) * (p2.Y - p2.X));
        var b = Mod((p1.Y + p1.X) * (p2.Y + p2.X));
        var c = Mod(p1.T * D2 * p2.T);
        var d = Mod(p1.Z * 2 * p2.Z);
        var e = Mod(b - a);
        var f = Mod(d - c);
        var g = Mod(d + c);
        var h = Mod(b + a);
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Double(Point p1)
    {
        var a = Mod(p1.X * p1.X);
        var b = Mod(p1.Y * p1.Y);
        var c = Mod(2 * p1.Z * p1.Z);
        var d = Mod(-a);
        var sum = p1.X + p1.Y;
        var e = Mod(sum * sum - a - b);
        var g = Mod(d + b);
        var f = Mod(g - c);
        var h = Mod(d - b);
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point ScalarMult(Point point, BigInteger scalar)
    {
        var result = Identity;
        var addend = point;
        var s = scalar;
        while (s > BigInteger.Zero)
        {
            if (!s.IsEven) result = Add(result, addend);
            addend = Double(addend);
            s >>= 1;
        }
        return result;
    }

    private static Point ScalarMultBase(BigInteger scalar) => ScalarMult(Base, scalar);

    /// <summary>The identity point's encoding (y = 1, x = 0).</summary>
    private static readonly byte[] IdentityEncoding = MakeIdentityEncoding();

    private static byte[] MakeIdentityEncoding() { var b = new byte[32]; b[0] = 1; return b; }

    /// <summary>True when the point is small-order ([8]P = identity:
    /// order dividing 8). Signatures under a small-order public key are
    /// forgeable by anyone — [k]A contributes nothing (or one of a few
    /// known values) to the verification equation — so such keys are
    /// not valid Ed25519 public keys for verification, enrollment, or
    /// import (D38 S1-WIN F2).</summary>
    private static bool IsSmallOrder(Point point) =>
        Encode(ScalarMult(point, 8)).SequenceEqual(IdentityEncoding);

    /// <summary>True when a 32-byte public-key encoding decodes to a
    /// small-order point. Undecodable encodings return false here —
    /// callers reject those on their own fail-closed paths.</summary>
    public static bool IsSmallOrderPublicKey(ReadOnlySpan<byte> publicKey)
    {
        var point = Decode(publicKey);
        return point is not null && IsSmallOrder(point.Value);
    }

    // ---- point encoding / decoding -------------------------------------

    private static byte[] Encode(Point point)
    {
        var x = point.AffineX();
        var y = point.AffineY();
        var outp = IntToLittleEndian(y, 32);
        if (!x.IsEven) outp[31] |= 0x80;
        return outp;
    }

    /// <summary>Decode a 32-byte encoding; null when it is not a valid point.</summary>
    private static Point? Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32) return null;
        var sign = (bytes[31] & 0x80) != 0;
        var yBytes = bytes.ToArray();
        yBytes[31] &= 0x7F;
        var y = LittleEndianToInt(yBytes);
        if (y >= P) return null;
        // x = sqrt((y^2 - 1) / (d y^2 + 1)), p = 5 mod 8 method.
        var yy = Mod(y * y);
        var u = Mod(yy - 1);
        var v = Mod(D * yy + 1);
        var xx = Mod(u * ModInverse(v));
        var x = BigInteger.ModPow(xx, (P - 5) / 8, P);
        x = Mod(x * xx); // x = xx^((p+3)/8), the RFC candidate
        var vx2 = Mod(v * x * x);
        if (vx2 == u) { /* good */ }
        else if (vx2 == Mod(-u)) x = Mod(x * SqrtM1);
        else return null;
        if (x == BigInteger.Zero && sign) return null;
        if (x.IsEven == sign) x = P - x; // need testBit(0) == sign
        return new Point(x, y, BigInteger.One, Mod(x * y));
    }

    // ---- key derivation --------------------------------------------------

    private static (BigInteger Scalar, byte[] Prefix, byte[] Hash) ExpandSeed(ReadOnlySpan<byte> seed)
    {
        var h = SHA512.HashData(seed);
        var aBytes = h.AsSpan(0, 32).ToArray();
        aBytes[0] &= 248;
        aBytes[31] &= 63;
        aBytes[31] |= 64;
        return (LittleEndianToInt(aBytes), h.AsSpan(32, 32).ToArray(), h);
    }

    /// <summary>Generate a fresh keypair: 32 random seed bytes + derived public key.</summary>
    public static (byte[] Seed, byte[] PublicKey) GenerateKeyPair()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        return (seed, DerivePublicKey(seed));
    }

    /// <summary>Derive the 32-byte public key from a 32-byte seed (RFC 8032 §5.1.5).</summary>
    public static byte[] DerivePublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));
        var (scalar, _, _) = ExpandSeed(seed);
        return Encode(ScalarMultBase(scalar));
    }

    /// <summary>DeviceId: lowercase hex SHA-256 of the 32-byte public key.</summary>
    public static string ComputeDeviceId(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32) throw new ArgumentException("Ed25519 public key must be 32 bytes.", nameof(publicKey));
        return Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
    }

    // ---- sign / verify ---------------------------------------------------

    /// <summary>Sign a message with a 32-byte seed (RFC 8032 §5.1.6). Returns 64 bytes.</summary>
    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));
        var (scalar, prefix, _) = ExpandSeed(seed);
        var publicKey = Encode(ScalarMultBase(scalar));

        var rHash = SHA512.HashData(Concat(prefix, message));
        var r = LittleEndianToInt(rHash) % L;
        var rEncoded = Encode(ScalarMultBase(r));

        var kHash = SHA512.HashData(Concat(Concat(rEncoded, publicKey), message));
        var k = LittleEndianToInt(kHash) % L;
        var s = (r + k * scalar) % L;

        var sig = new byte[64];
        rEncoded.CopyTo(sig, 0);
        IntToLittleEndian(s, 32).CopyTo(sig, 32);
        return sig;
    }

    /// <summary>Verify a signature (RFC 8032 §5.1.7, cofactored-less
    /// equation [S]B = R + [k]A with canonical S). Fail-closed:
    /// malformed input of any kind returns false, never throws.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        try
        {
            if (publicKey.Length != 32 || signature.Length != 64) return false;
            var s = LittleEndianToInt(signature.Slice(32, 32));
            if (s.Sign < 0 || s >= L) return false; // non-canonical S
            var aPoint = Decode(publicKey);
            if (aPoint is null) return false;
            if (IsSmallOrder(aPoint.Value)) return false; // forgeable key (F2)
            var rEncoded = signature.Slice(0, 32).ToArray();
            var rPoint = Decode(rEncoded);
            if (rPoint is null) return false;
            if (IsSmallOrder(rPoint.Value)) return false;

            var kHash = SHA512.HashData(Concat(Concat(rEncoded, publicKey), message));
            var k = LittleEndianToInt(kHash) % L;

            var left = Encode(ScalarMultBase(s));
            var right = Encode(Add(rPoint.Value, ScalarMult(aPoint.Value, k)));
            return CryptographicOperations.FixedTimeEquals(left, right);
        }
        catch
        {
            return false; // fail closed on any malformed input
        }
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var outp = new byte[a.Length + b.Length];
        a.CopyTo(outp);
        b.CopyTo(outp.AsSpan(a.Length));
        return outp;
    }
}
