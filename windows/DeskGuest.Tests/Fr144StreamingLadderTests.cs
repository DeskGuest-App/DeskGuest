using DeskGuest.Shared.Streaming;

namespace DeskGuest.Tests;

/// <summary>
/// FR-144 (GitHub issue #45) — the streaming encode ladder's
/// bottom rung: the bundled software encoder (OpenH264), for
/// machines whose Media Foundation stack cannot encode. The
/// laptop conviction stands (2026-11-25): every MF H.264 MFT
/// refuses constructed media types there, Microsoft's own
/// SinkWriter control fails identically, and DISM/SFC repair
/// changed nothing — so live sessions ride this rung there.
///
/// The ABI facts are pinned directly (they were earned from the
/// vendor's 2.6.0 headers + source and the conviction probe's
/// TEST 4); the conversion and bitstream assembly are pinned on
/// synthetic frames; the ladder semantics are pinned on fake
/// rungs; the Session Agent wiring is pinned by source (W73
/// pattern — the agent is a WPF exe the test project does not
/// reference). The live proof — a real stream carried by this
/// rung on the laptop — is in BUILD-LOG (FR-144 entry).
/// </summary>
public class Fr144StreamingLadderTests
{
    // ---- The ABI, pinned -----------------------------------------

    [Fact]
    public void Abi_UsageType_IsScreenContentRealTime_TheOnlyExtLegalScreenValue()
    {
        // codec_app_def.h: CAMERA_VIDEO_REAL_TIME=0,
        // SCREEN_CONTENT_REAL_TIME=1, CAMERA_VIDEO_NON_REAL_TIME=2.
        // ParamValidationExt (encoder_ext.cpp v2.6.0) accepts ONLY
        // 0 and 1 for InitializeExt; the value 2 is the exact
        // failure the probe shipped with ("Invalid usage type = 2").
        Assert.Equal(1, OpenH264Abi.UsageScreenContentRealTime);
        Assert.Equal(1, OpenH264Abi.RcBitrateMode);
        Assert.Equal(23, OpenH264Abi.VideoFormatI420);
        Assert.Equal("openh264-2.6.0-win64.dll", OpenH264Abi.DllFileName);
    }

    [Fact]
    public void Abi_ParamAndLayerOffsets_MatchThe260Headers()
    {
        Assert.Equal(0, OpenH264Abi.ParamUsageType);
        Assert.Equal(4, OpenH264Abi.ParamPicWidth);
        Assert.Equal(28, OpenH264Abi.ParamSpatialLayerNum);
        Assert.Equal(32, OpenH264Abi.LayerVideoWidth);
        Assert.Equal(48, OpenH264Abi.LayerMaxSpatialBitrate);
        Assert.Equal(56, OpenH264Abi.LayerInfoSize);
        Assert.Equal(16, OpenH264Abi.LayerNalCount);
        Assert.Equal(24, OpenH264Abi.LayerNalLengths);
        Assert.Equal(32, OpenH264Abi.LayerBsBuf);
        Assert.Equal(8 + 128 * 56 + 16, OpenH264Abi.BsInfoBufferBytes);
    }

    // ---- Padding + colour conversion ------------------------------

    [Fact]
    public void PaddedDimension_RoundsUpTo16_AlignedPassesThrough()
    {
        Assert.Equal(1088, I420Conversion.PaddedDimension(1080));
        Assert.Equal(720, I420Conversion.PaddedDimension(720));
        Assert.Equal(1920, I420Conversion.PaddedDimension(1920));
        Assert.Equal(16, I420Conversion.PaddedDimension(2));
        Assert.Equal(16, I420Conversion.PaddedDimension(16));
    }

    [Fact]
    public void Nv12ToI420Padded_DeinterleavesChroma_AndReplicatesEdges()
    {
        // 4×2 NV12: luma rows [1,2,3,4] / [5,6,7,8]; one chroma
        // row of two samples: U0=101 V0=102 U1=103 V1=104.
        var nv12 = new byte[]
        {
            1, 2, 3, 4,
            5, 6, 7, 8,
            101, 102, 103, 104,
        };
        var i420 = I420Conversion.Nv12ToI420Padded(nv12, 4, 2, 16, 16);
        Assert.Equal(16 * 16 + 8 * 8 * 2, i420.Length);
        // Luma: source rows at the top-left, right edge replicated,
        // bottom rows replicate the last source row.
        Assert.Equal(new byte[] { 1, 2, 3, 4, 4 }, i420.AsSpan(0, 5).ToArray());
        Assert.Equal(new byte[] { 5, 6, 7, 8, 8 }, i420.AsSpan(16, 5).ToArray());
        Assert.Equal(new byte[] { 5, 6, 7, 8 }, i420.AsSpan(2 * 16, 4).ToArray());
        // Chroma planes: U then V, deinterleaved, edges replicated.
        var u = 16 * 16; var v = u + 8 * 8;
        Assert.Equal(new byte[] { 101, 103, 103 }, i420.AsSpan(u, 3).ToArray());
        Assert.Equal(new byte[] { 102, 104, 104 }, i420.AsSpan(v, 3).ToArray());
        Assert.Equal((byte)101, i420[u + 8]); // second chroma row replicates the first
    }

    // ---- Bitstream assembly ----------------------------------------

    private static byte[] Nal(byte type, params byte[] payload)
        => new byte[] { 0, 0, 0, 1, type }.Concat(payload).ToArray();

    [Fact]
    public void ConcatAu_JoinsEveryLayerInOrder_ParameterSetsThenSlices()
    {
        var sps = Nal(7, 0xAA);
        var pps = Nal(8, 0xBB);
        var idr = Nal(5, 0xCC, 0xDD);
        var au = OpenH264Bitstream.ConcatAu(new[]
        {
            new LayerBitstream(new[] { sps.Length, pps.Length }, sps.Concat(pps).ToArray()),
            new LayerBitstream(new[] { idr.Length }, idr),
        });
        Assert.Equal(sps.Concat(pps).Concat(idr).ToArray(), au);
        // The assembled AU is a valid keyframe by the product's
        // own validator — the exact shape TEST 4 produces live.
        Assert.True(H264.IsValidAccessUnit(au, expectKeyframe: true));
    }

    [Fact]
    public void ConcatAu_LayerZeroAlone_IsNotAKeyframe_RegressionForTheProbeBug()
    {
        // The probe's first TEST 4 read only layer 0 (SPS/PPS, no
        // slice) and reported the rung broken. Pinned so the
        // assembly rule is never "simplified" back.
        var sps = Nal(7, 0xAA);
        var pps = Nal(8, 0xBB);
        var au = OpenH264Bitstream.ConcatAu(new[]
        {
            new LayerBitstream(new[] { sps.Length, pps.Length }, sps.Concat(pps).ToArray()),
        });
        Assert.False(H264.IsValidAccessUnit(au, expectKeyframe: true));
    }

    // ---- Ladder semantics -------------------------------------------

    private sealed class FakeEncoder
    {
        public FakeEncoder(string name) => Name = name;
        public string Name { get; }
    }

    private static (string, Func<(bool, FakeEncoder?, string)>) Rung(string name, bool ok, List<string> attempted)
        => (name, () =>
        {
            attempted.Add(name);
            return ok ? (true, new FakeEncoder(name), "") : (false, null, $"{name} refused");
        });

    [Fact]
    public void Ladder_FirstSuccessWins_LaterRungsNeverAttempted()
    {
        var attempted = new List<string>();
        var ok = FallbackLadder.TryInOrder(new[]
        {
            Rung("one", false, attempted),
            Rung("two", true, attempted),
            Rung("three", true, attempted),
        }, out var value, out var error);
        Assert.True(ok);
        Assert.Equal("two", value!.Name);
        Assert.Equal("", error);
        Assert.Equal(new[] { "one", "two" }, attempted);
    }

    [Fact]
    public void Ladder_AllFail_ErrorNamesEveryRungAndReason()
    {
        var attempted = new List<string>();
        var ok = FallbackLadder.TryInOrder(new[]
        {
            Rung("MF hardware", false, attempted),
            Rung("MF software", false, attempted),
            Rung("bundled", false, attempted),
        }, out var value, out var error);
        Assert.False(ok);
        Assert.Null(value);
        Assert.Contains("MF hardware: MF hardware refused", error);
        Assert.Contains("MF software: MF software refused", error);
        Assert.Contains("bundled: bundled refused", error);
        Assert.Equal(3, attempted.Count);
    }

    // ---- Source pins (W73 pattern) ----------------------------------

    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(string.Join("/", parts) + " not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Source_LadderWalksThreeRungsInOrder_AndStreamEngineUsesIt()
    {
        var ladder = SrcFile("DeskGuest.SessionAgent", "StreamEncoderLadder.cs");
        var hw = ladder.IndexOf("Media Foundation hardware", StringComparison.Ordinal);
        var sw = ladder.IndexOf("Media Foundation software", StringComparison.Ordinal);
        var bundled = ladder.IndexOf("Bundled software (OpenH264)", StringComparison.Ordinal);
        Assert.True(hw >= 0 && sw > hw && bundled > sw,
            "rungs must be declared in ladder order: MF hardware, MF software, bundled");
        Assert.Contains("FallbackLadder.TryInOrder", ladder);

        var engine = SrcFile("DeskGuest.SessionAgent", "StreamEngine.cs");
        Assert.Contains("StreamEncoderLadder.TryCreate", engine);
        Assert.DoesNotContain("H264Encoder.TryCreate(", engine);
    }

    [Fact]
    public void Source_OpenH264Rung_IsHonestlyNamed_AndShipsTheDll()
    {
        var enc = SrcFile("DeskGuest.SessionAgent", "OpenH264Encoder.cs");
        Assert.Contains("Bundled software H.264 encoder (OpenH264)", enc);
        Assert.Contains("Hardware => false", enc);
        Assert.Contains("OpenH264Abi.DllFileName", enc);
        Assert.Contains("AppContext.BaseDirectory", enc);
        // codec_api.h: the create export writes the encoder
        // through an out parameter and returns a result code.
        // A pointer-returning model crashes inside TryCreate —
        // observed live on the first proof run (2026-11-25).
        Assert.Contains("delegate int CreateEncoderFn(out IntPtr encoder)", enc);
        Assert.Contains("create(out enc._enc)", enc);

        var csproj = SrcFile("DeskGuest.SessionAgent", "DeskGuest.SessionAgent.csproj");
        Assert.Contains("openh264-2.6.0-win64.dll", csproj);
        Assert.Contains("CopyToOutputDirectory", csproj);
    }
}
