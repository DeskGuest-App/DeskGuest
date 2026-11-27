namespace DeskGuest.Shared.Streaming;

/// <summary>
/// The streaming encode ladder's bottom rung: a bundled software
/// H.264 encoder (OpenH264), for machines whose Media Foundation
/// stack cannot encode — the fallback-ladder law (BUILD-PROGRAMME,
/// 2026-11-24) names this rung explicitly: MF hardware → MF
/// software → bundled software encoder, descent automatic, the
/// active rung honestly shown. This file carries the rung's pure,
/// pinnable facts — the OpenH264 C ABI as read from the 2.6.0
/// headers (codec_api.h / codec_app_def.h / codec_def.h, copies in
/// the project research folder) and proven against the shipped DLL
/// by the conviction probe's TEST 4 — while the native wrapper
/// lives in the Session Agent (OpenH264Encoder.cs).
/// </summary>
public static class OpenH264Abi
{
    /// <summary>openh264-2.6.0-win64.dll, Cisco's BSD-licensed
    /// binary, shipped beside the Session Agent.</summary>
    public const string DllFileName = "openh264-2.6.0-win64.dll";

    // EUsageType (codec_app_def.h): CAMERA_VIDEO_REAL_TIME = 0,
    // SCREEN_CONTENT_REAL_TIME = 1, CAMERA_VIDEO_NON_REAL_TIME = 2,
    // SCREEN_CONTENT_NON_REAL_TIME = 3. InitializeExt accepts ONLY
    // 0 and 1 — ParamValidationExt (encoder_ext.cpp, v2.6.0)
    // rejects anything else with "Invalid usage type". The probe's
    // original value of 2 (written believing it meant screen
    // content) is why TEST 4 failed until 2026-11-25.
    public const int UsageScreenContentRealTime = 1;

    /// <summary>RC_MODES (codec_app_def.h): RC_QUALITY_MODE = 0,
    /// RC_BITRATE_MODE = 1.</summary>
    public const int RcBitrateMode = 1;

    /// <summary>EVideoFormatType (codec_def.h): videoFormatI420.</summary>
    public const int VideoFormatI420 = 23;

    // SEncParamExt field offsets (x64, codec_app_def.h): the base
    // fields, then sSpatialLayers[0].
    public const int ParamUsageType = 0;
    public const int ParamPicWidth = 4;
    public const int ParamPicHeight = 8;
    public const int ParamTargetBitrate = 12;
    public const int ParamRcMode = 16;
    public const int ParamMaxFrameRate = 20;
    public const int ParamTemporalLayerNum = 24;
    public const int ParamSpatialLayerNum = 28;
    public const int LayerVideoWidth = 32;
    public const int LayerVideoHeight = 36;
    public const int LayerFrameRate = 40;
    public const int LayerSpatialBitrate = 44;
    public const int LayerMaxSpatialBitrate = 48;

    /// <summary>sizeof(SEncParamExt) is well under this; the
    /// oversized zeroed buffer is the probe-proven calling
    /// pattern (GetDefaultParams fills what it needs).</summary>
    public const int ParamBufferBytes = 4096;

    // SFrameBSInfo (codec_app_def.h): iLayerNum at 0, then
    // sLayerInfo[MAX_LAYER_NUM_OF_FRAME] at offset 8, each
    // SLayerBSInfo 56 bytes: iNalCount at +16,
    // pNalLengthInByte at +24, pBsBuf at +32.
    public const int MaxLayersPerFrame = 128;
    public const int LayerInfoOffset = 8;
    public const int LayerInfoSize = 56;
    public const int LayerNalCount = 16;
    public const int LayerNalLengths = 24;
    public const int LayerBsBuf = 32;
    public const int BsInfoBufferBytes = LayerInfoOffset + MaxLayersPerFrame * LayerInfoSize + 16;

    // SSourcePicture (codec_app_def.h): iColorFormat at 0,
    // iStride[4] at 4, pData[4] at 24 (x64 alignment), iPicWidth
    // at 56, iPicHeight at 60, uiTimeStamp at 64.
    public const int PicColorFormat = 0;
    public const int PicStride = 4;
    public const int PicData = 24;
    public const int PicWidth = 56;
    public const int PicHeight = 60;
    public const int PicTimeStamp = 64;
    public const int PicBufferBytes = 128;
}

/// <summary>NV12 → I420 conversion with edge-replication padding
/// to a multiple of 16: ParamValidationExt refuses spatial layers
/// whose dimensions are not multiples of 16, and real desktops are
/// routinely not (1920×1080 → 1920×1088). The padded rows/columns
/// replicate the nearest edge pixel — the stream's frame header
/// keeps carrying the true capture dimensions; the padding is a
/// named property of this rung, never disguised.</summary>
public static class I420Conversion
{
    /// <summary>Round a dimension UP to the next multiple of 16
    /// (already-aligned values pass through).</summary>
    public static int PaddedDimension(int value) => (value + 15) & ~15;

    /// <summary>Convert one NV12 frame (w×h, both even) into a
    /// padded I420 frame of pw×ph (the padded dimensions of w/h).
    /// Output layout: Y plane (pw*ph), U plane ((pw/2)*(ph/2)),
    /// V plane likewise.</summary>
    public static byte[] Nv12ToI420Padded(ReadOnlySpan<byte> nv12, int width, int height, int paddedWidth, int paddedHeight)
    {
        var ySize = width * height;
        var outY = paddedWidth * paddedHeight;
        var outC = (paddedWidth / 2) * (paddedHeight / 2);
        var result = new byte[outY + outC * 2];
        // Luma.
        for (var y = 0; y < paddedHeight; y++)
        {
            var srcRow = Math.Min(y, height - 1) * width;
            var dstRow = y * paddedWidth;
            nv12.Slice(srcRow, width).CopyTo(result.AsSpan(dstRow, width));
            var edge = result[dstRow + width - 1];
            result.AsSpan(dstRow + width, paddedWidth - width).Fill(edge);
        }
        // Chroma: NV12 interleaves U,V per 2×2 block; I420 planes
        // them separately at half resolution in both axes.
        var cw = width / 2; var ch = height / 2;
        var pcw = paddedWidth / 2; var pch = paddedHeight / 2;
        for (var comp = 0; comp < 2; comp++)
        {
            var plane = outY + comp * outC;
            for (var y = 0; y < pch; y++)
            {
                var sy = Math.Min(y, ch - 1);
                var dstRow = plane + y * pcw;
                for (var x = 0; x < pcw; x++)
                {
                    var sx = Math.Min(x, cw - 1);
                    result[dstRow + x] = nv12[ySize + sy * width + sx * 2 + comp];
                }
            }
        }
        return result;
    }
}

/// <summary>One layer entry of an OpenH264 output frame: its NAL
/// lengths and the bytes they index into.</summary>
public sealed record LayerBitstream(IReadOnlyList<int> NalLengths, byte[] Data);

/// <summary>Assembling an access unit from OpenH264's layered
/// output. The encoder returns parameter sets in their OWN layer
/// entry, ahead of the layer carrying the slices — an AU is the
/// concatenation of every layer's NALs in order. (Reading layer 0
/// alone yields SPS/PPS and no slice; the conviction probe's
/// TEST 4 did exactly that in its first form.)</summary>
public static class OpenH264Bitstream
{
    public static byte[] ConcatAu(IReadOnlyList<LayerBitstream> layers)
    {
        var total = 0;
        foreach (var layer in layers)
            foreach (var len in layer.NalLengths)
                if (len > 0) total += len;
        var au = new byte[total];
        var at = 0;
        foreach (var layer in layers)
        {
            var consumed = 0;
            foreach (var len in layer.NalLengths)
            {
                if (len <= 0) continue;
                var take = Math.Min(len, layer.Data.Length - consumed);
                if (take <= 0) break;
                layer.Data.AsSpan(consumed, take).CopyTo(au.AsSpan(at, take));
                at += take;
                consumed += len;
            }
        }
        return au.AsSpan(0, at).ToArray();
    }
}

/// <summary>The fallback-ladder runner (BUILD-PROGRAMME ladder
/// law): rungs are attempted in order, the first success carries
/// the capability, and a total failure names EVERY rung and its
/// reason — descent is a designed behaviour with an honest error,
/// never a silent cliff.</summary>
public static class FallbackLadder
{
    public static bool TryInOrder<T>(
        IReadOnlyList<(string Name, Func<(bool Ok, T? Value, string Error)> Attempt)> rungs,
        out T? value, out string error) where T : class
    {
        var errors = new List<string>();
        foreach (var (name, attempt) in rungs)
        {
            var (ok, v, err) = attempt();
            if (ok && v is not null) { value = v; error = ""; return true; }
            errors.Add($"{name}: {(string.IsNullOrWhiteSpace(err) ? "failed without a reason" : err)}");
        }
        value = null;
        error = "every rung failed — " + string.Join("; ", errors);
        return false;
    }
}
