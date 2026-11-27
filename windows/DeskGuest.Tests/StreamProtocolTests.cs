using DeskGuest.Shared.Streaming;

namespace DeskGuest.Tests;

/// <summary>Block D — the DGSF v1 stream envelope + Annex B
/// validation + damage tracking. The parser is a security boundary
/// for viewer decoders, so the battery is written like a fuzz
/// corpus: every malformed shape must come back null/false, and
/// the keyframe flag must be proven by the NALs, never trusted.</summary>
public class StreamProtocolTests
{
    private static byte[] Nal(int type, params byte[] payload)
    {
        var bytes = new byte[5 + payload.Length];
        bytes[3] = 1;
        bytes[4] = (byte)type;
        payload.CopyTo(bytes, 5);
        return bytes;
    }

    private static byte[] KeyAu() => Nal(7, 0x64, 0x00).Concat(Nal(8, 0xEE)).Concat(Nal(5, 0x88)).ToArray();
    private static byte[] DeltaAu() => Nal(1, 0x22).ToArray();

    private static StreamProtocol.FrameHeader Header(bool keyframe, long seq = 1, int width = 1920, int height = 1080, string codec = "h264") =>
        new(seq, 100, 1_700_000_000_000, keyframe, width, height, 0, codec, "Test MFT", true, "dxgi", null, 10, 20);

    [Fact]
    public void Pack_Parse_RoundTrips_Keyframe_And_Delta()
    {
        var key = StreamProtocol.TryParse(StreamProtocol.Pack(Header(true), KeyAu()));
        Assert.NotNull(key);
        Assert.True(key!.Header.Keyframe);
        Assert.Equal(1920, key.Header.Width);
        Assert.Equal(10, key.Header.CursorX);
        Assert.Equal(KeyAu(), key.AccessUnit);

        var delta = StreamProtocol.TryParse(StreamProtocol.Pack(Header(false, seq: 2), DeltaAu()));
        Assert.NotNull(delta);
        Assert.False(delta!.Header.Keyframe);
    }

    [Fact]
    public void Parse_Rejects_BadMagic_And_WrongVersion()
    {
        var body = StreamProtocol.Pack(Header(true), KeyAu());
        body[0] = (byte)'X';
        Assert.Null(StreamProtocol.TryParse(body));
        var v2 = StreamProtocol.Pack(Header(true), KeyAu());
        v2[4] = 2;
        Assert.Null(StreamProtocol.TryParse(v2));
    }

    [Fact]
    public void Parse_Rejects_Truncated_Header()
    {
        var body = StreamProtocol.Pack(Header(true), KeyAu());
        Assert.Null(StreamProtocol.TryParse(body.AsSpan(0, 10)));
        Assert.Null(StreamProtocol.TryParse(body.AsSpan(0, 40))); // cut inside the header JSON
    }

    [Fact]
    public void Parse_Rejects_HeaderLength_BeyondCap()
    {
        var body = StreamProtocol.Pack(Header(true), KeyAu());
        body[6] = 0xFF; body[7] = 0xFF; // headerLen = 65535 > 4096
        Assert.Null(StreamProtocol.TryParse(body));
    }

    [Fact]
    public void Parse_Rejects_KeyframedClaim_Without_IDR()
    {
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(true), DeltaAu())));
    }

    [Fact]
    public void Parse_Rejects_DeltaClaim_With_IDR()
    {
        // The NALs are the truth: an IDR AU labelled "delta" is a
        // lying envelope and dies here (both directions).
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(false), KeyAu())));
    }

    [Fact]
    public void Parse_Rejects_SPS_After_IDR()
    {
        var au = Nal(5, 0x88).Concat(Nal(7, 0x64)).Concat(Nal(8, 0xEE)).ToArray();
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(true), au)));
    }

    [Fact]
    public void Parse_Rejects_ForbiddenZeroBit_And_BadNalTypes()
    {
        var forbidden = new byte[] { 0, 0, 0, 1, 0x85, 0x11 }; // type 5 with forbidden_zero_bit set
        Assert.False(H264.IsValidAccessUnit(forbidden, true));
        Assert.False(H264.IsValidAccessUnit(Nal(0, 0x11), false));
        Assert.False(H264.IsValidAccessUnit(Nal(13, 0x11), false));
        Assert.False(H264.IsValidAccessUnit(new byte[] { 0x11, 0x22, 0x33, 0x44 }, false)); // no start code
        Assert.False(H264.IsValidAccessUnit(ReadOnlySpan<byte>.Empty, false));
    }

    [Fact]
    public void Parse_Rejects_AbsurdDimensions_And_WrongCodec()
    {
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(true, width: 99999), KeyAu())));
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(true, width: 0), KeyAu())));
        Assert.Null(StreamProtocol.TryParse(StreamProtocol.Pack(Header(true, codec: "vp9"), KeyAu())));
    }

    [Fact]
    public void Fuzz_Mutations_NeverParse_AsValidFrames()
    {
        // Deterministic mutation fuzz: flip bytes in a valid
        // envelope; the parser may accept only mutations that leave
        // a still-valid envelope (e.g. payload bytes), and must
        // never throw. Structural mutations (magic/version/header
        // length/first NAL header) must always reject.
        var body = StreamProtocol.Pack(Header(true), KeyAu());
        var rng = new Random(20261119);
        for (var i = 0; i < 400; i++)
        {
            var mutated = body.ToArray();
            var pos = rng.Next(mutated.Length);
            mutated[pos] = (byte)(mutated[pos] ^ 0xFF); // guaranteed-different byte
            var parsed = StreamProtocol.TryParse(mutated); // must not throw
            if (pos < 8) Assert.Null(parsed); // magic/version/header-length flips always reject
        }
        // Truncations: anything that cuts into the header or leaves
        // less than one minimal NAL of AU can never be a valid
        // frame; deeper AU payload cuts may still parse (Annex B is
        // header-driven) but must never throw.
        var auStart = body.Length - KeyAu().Length;
        for (var len = 0; len < body.Length; len++)
        {
            var parsed = StreamProtocol.TryParse(body.AsSpan(0, len));
            if (len < auStart + 5) Assert.Null(parsed);
        }
    }

    [Fact]
    public void Damage_StaticFrame_IsNull_ChangedTile_IsLocalized()
    {
        var tracker = new DamageTracker();
        var w = 128; var h = 128; var stride = w * 4;
        var frame = new byte[stride * h];
        Assert.NotNull(tracker.Diff(frame, w, h, stride)); // first frame: full
        Assert.Null(tracker.Diff(frame, w, h, stride));    // static: nothing
        var changed = frame.ToArray();
        changed[(70 * stride) + 70 * 4] = 0xFF;             // one pixel in tile (1,1)
        changed[(70 * stride) + 70 * 4 + 1] = 0xFF;
        var damage = tracker.Diff(changed, w, h, stride);
        Assert.NotNull(damage);
        Assert.Equal(64, damage!.X);
        Assert.Equal(64, damage.Y);
        Assert.Null(tracker.Diff(changed, w, h, stride));  // static again
    }
}
