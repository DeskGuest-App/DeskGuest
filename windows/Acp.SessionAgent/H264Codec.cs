using System.Runtime.InteropServices;

namespace Acp.SessionAgent;

/// <summary>One encoded access unit out of the H.264 encoder.</summary>
internal sealed record EncodedAu(byte[] Data, bool Keyframe);

/// <summary>One rung of the streaming encode ladder (the fallback
/// law: MF hardware → MF software → bundled software encoder).
/// StreamEngine holds whichever rung started; the rung's
/// Description and Hardware flag ride the stream_start result,
/// the stats, and every frame header, so the active rung is
/// honestly shown wherever the stream is described. The choice is
/// made once per stream start and never revisited mid-stream —
/// a ladder that cannot oscillate cannot flap.</summary>
internal interface IH264StreamEncoder : IDisposable
{
    bool Hardware { get; }
    string Description { get; }
    int Width { get; }
    int Height { get; }
    void RequestKeyFrame();
    IReadOnlyList<EncodedAu> Encode(ReadOnlySpan<byte> nv12, long time100ns, long duration100ns);
}

/// <summary>BD-WIN-AGENT F12: Media Foundation process lifetime,
/// reference-counted. The pre-fix code called MFStartup on EVERY
/// encoder/decoder creation and never called MFShutdown at all —
/// an unbalanced, leaking startup contract. Now the first live
/// codec starts MF and the last one's Dispose shuts it down.</summary>
internal static class MfLifetime
{
    private static readonly object Gate = new();
    private static int _refs;

    public static bool Acquire(out string error)
    {
        lock (Gate)
        {
            if (_refs > 0) { _refs++; error = ""; return true; }
            var hr = Mf.MFStartup(Mf.MF_VERSION, Mf.MFSTARTUP_LITE);
            if (!Mf.Ok(hr)) { error = $"MFStartup failed {Mf.Hr(hr)}"; return false; }
            _refs = 1;
            error = "";
            return true;
        }
    }

    public static void Release()
    {
        lock (Gate)
        {
            if (_refs <= 0) return;
            _refs--;
            if (_refs == 0) { try { Mf.MFShutdown(); } catch { } }
        }
    }
}

/// <summary>
/// Media Foundation H.264 encoder wrapper (Block D). Activation
/// order is the honesty contract: (1) MFTEnumEx over the VIDEO_ENCODER
/// category with the HARDWARE flag, NV12 in / H.264 out — the
/// machine's hardware encoder (NVENC / AMF / QuickSync class) when
/// one is registered; (2) the same enumeration without the flag —
/// the in-box Microsoft software encoder. The wrapper reports which
/// path produced the transform (<see cref="Hardware"/>,
/// <see cref="Description"/>) and the stream header repeats it, so
/// no surface ever claims hardware encoding that did not happen.
/// Every setup step is named; a failure returns the step + HRESULT
/// instead of throwing across the IPC boundary.
///
/// Interop note (2026-11-19, probe-verified on the reference laptop):
/// every attribute-family object (media types, samples, buffers,
/// attribute stores) is driven by raw vtable pointer (AttrPtr /
/// BufferPtr / SamplePtr / TransformPtr in StreamNative.cs) because
/// those objects refuse QueryInterface for their SDK-documented
/// IIDs on this machine while serving every vtable call correctly.
/// IMFTransform itself is held as an RCW — its IID resolves — and
/// only its value-only methods are called through it.
/// </summary>
internal sealed class H264Encoder : IH264StreamEncoder
{
    private IMFTransform? _mft;
    private IntPtr _mftPtr;
    private ICodecAPI? _codecApi;
    private bool _async;
    private bool _holdsMf;

    public bool Hardware { get; private set; }
    public string Description { get; private set; } = "";
    public int Width { get; private set; }
    public int Height { get; private set; }

    public static bool TryCreate(int width, int height, int fps, int bitrateBps, out H264Encoder? encoder, out string error)
    {
        // Both Media Foundation passes (hardware, then software);
        // the streaming ladder (StreamEncoderLadder) walks the
        // same passes as separate rungs before descending to the
        // bundled software encoder.
        if (TryCreatePass(hardware: true, width, height, fps, bitrateBps, out encoder, out error)) return true;
        return TryCreatePass(hardware: false, width, height, fps, bitrateBps, out encoder, out error);
    }

    /// <summary>One Media Foundation pass of the encode ladder.
    /// BD-WIN-AGENT F12: MF lifetime is reference-counted
    /// (MfLifetime) — started once per process, shut down when
    /// the last codec disposes. Every enumerated MFT gets an
    /// activate+configure attempt: vendor MFTs differ in what
    /// they accept, and the first one that activates is not
    /// necessarily one that will take the stream's types (the
    /// first hardware MFT on the reference laptop activates, then
    /// refuses the H.264 output type with MF_E_INVALIDMEDIATYPE —
    /// probe-verified 2026-11-19).</summary>
    internal static bool TryCreatePass(bool hardware, int width, int height, int fps, int bitrateBps, out H264Encoder? encoder, out string error)
    {
        encoder = null;
        if (!MfLifetime.Acquire(out error)) return false;
        if (!TryPass(hardware, width, height, fps, bitrateBps, out var enc, out error))
        {
            MfLifetime.Release();
            return false;
        }
        enc!._holdsMf = true;
        encoder = enc;
        error = "";
        return true;
    }

    private static bool TryPass(bool hardware, int width, int height, int fps, int bitrateBps, out H264Encoder? enc, out string error)
    {
        enc = null;
        error = "";
        var input = new Mf.MftRegisterTypeInfo { GuidMajorType = Mf.MediaTypeVideo, GuidSubtype = Mf.FormatNV12 };
        var output = new Mf.MftRegisterTypeInfo { GuidMajorType = Mf.MediaTypeVideo, GuidSubtype = Mf.FormatH264 };
        var flags = Mf.MFT_ENUM_FLAG_SYNCMFT | Mf.MFT_ENUM_FLAG_ASYNCMFT | Mf.MFT_ENUM_FLAG_SORTANDFILTER
                    | (hardware ? Mf.MFT_ENUM_FLAG_HARDWARE : 0u);
        var hr = Mf.MFTEnumEx(Mf.CategoryVideoEncoder, flags, input, output, out var activates, out var count);
        if (!Mf.Ok(hr)) { error = $"MFTEnumEx({(hardware ? "hardware" : "any")}) failed {Mf.Hr(hr)}"; return false; }
        if (count == 0 || activates == IntPtr.Zero)
        {
            error = hardware ? "no hardware H.264 encoder MFT registered" : "no H.264 encoder MFT registered at all";
            return false;
        }
        var lastError = "";
        try
        {
            for (var i = 0; i < count; i++)
            {
                var candidate = new H264Encoder();
                var activate = Marshal.ReadIntPtr(activates, i * IntPtr.Size);
                if (!candidate.ActivateOne(activate, hardware, out var actError))
                {
                    lastError = actError;
                    candidate.Dispose();
                    continue;
                }
                if (!candidate.Configure(width, height, fps, bitrateBps, out var cfgError))
                {
                    lastError = cfgError;
                    candidate.Dispose();
                    continue;
                }
                enc = candidate;
                return true;
            }
        }
        finally
        {
            for (var i = 0; i < count; i++)
            {
                var activate = Marshal.ReadIntPtr(activates, i * IntPtr.Size);
                if (activate != IntPtr.Zero) Marshal.Release(activate);
            }
            Marshal.FreeCoTaskMem(activates);
        }
        error = lastError.Length > 0 ? lastError : $"no enumerated {(hardware ? "hardware " : "")}encoder would activate and configure";
        return false;
    }

    /// <summary>Activate ONE enumerated MFT (the caller walks the
    /// enumeration and the activation list's lifetime).</summary>
    private bool ActivateOne(IntPtr activate, bool hardware, out string error)
    {
        error = "";
        var hr = ActivateHelper.ActivateTransform(activate, out var mft, out var mftPtrRaw);
        if (!Mf.Ok(hr) || mft is null)
        {
            error = $"encoder MFT ActivateObject {Mf.Hr(hr)}";
            return false;
        }
        _mft = mft;
        _mftPtr = mftPtrRaw; // borrowed raw interface pointer (never Released)
        Hardware = hardware;
        Description = hardware ? "Media Foundation hardware H.264 encoder MFT" : "Media Foundation H.264 encoder MFT (software)";
        // Async MFTs (all hardware ones) must be unlocked
        // before use; sync MFTs ignore the attribute.
        if (mft.GetAttributes(out var attrsPtr) >= 0 && attrsPtr != IntPtr.Zero)
        {
            // Raw-vtable attribute access: the pointer
            // IS IMFAttributes; no IID is resolved
            // (see AttrPtr in StreamNative.cs).
            AttrPtr.GetUInt32(attrsPtr, Mf.TransformAsyncUnlock, out var asyncFlag);
            _async = asyncFlag != 0;
            if (_async) AttrPtr.SetUInt32(attrsPtr, Mf.TransformAsyncUnlock, 1);
            AttrPtr.SetUInt32(attrsPtr, Mf.LowLatency, 1);
            Marshal.Release(attrsPtr);
        }
        try { _codecApi = (ICodecAPI)Marshal.GetObjectForIUnknown(Marshal.GetIUnknownForObject(mft)); }
        catch { _codecApi = null; }
        return true;
    }

    private bool Configure(int width, int height, int fps, int bitrateBps, out string error)
    {
        error = "";
        Width = width; Height = height;
        var mft = _mft!;
        // Output type FIRST (encoder MFT convention), then input.
        var hr = Mf.MFCreateMediaType(out var outType);
        if (!Mf.Ok(hr)) { error = $"MFCreateMediaType(out) {Mf.Hr(hr)}"; return false; }
        try
        {
            AttrPtr.SetGUID(outType, Mf.MtMajorType, Mf.MediaTypeVideo);
            AttrPtr.SetGUID(outType, Mf.MtSubtype, Mf.FormatH264);
            AttrPtr.SetUInt32(outType, Mf.MtAvgBitrate, (uint)bitrateBps);
            AttrPtr.SetUInt64(outType, Mf.MtFrameSize, ((ulong)(uint)width << 32) | (uint)height);
            AttrPtr.SetUInt64(outType, Mf.MtFrameRate, ((ulong)(uint)fps << 32) | 1u);
            AttrPtr.SetUInt64(outType, Mf.MtPixelAspectRatio, (1UL << 32) | 1u);
            AttrPtr.SetUInt32(outType, Mf.MtInterlaceMode, 2); // MFVideoInterlace_Progressive
            hr = Mf.MFCreateMediaType(out var inType);
            if (!Mf.Ok(hr)) { error = $"MFCreateMediaType(in) {Mf.Hr(hr)}"; return false; }
            try
            {
                AttrPtr.SetGUID(inType, Mf.MtMajorType, Mf.MediaTypeVideo);
                AttrPtr.SetGUID(inType, Mf.MtSubtype, Mf.FormatNV12);
                AttrPtr.SetUInt64(inType, Mf.MtFrameSize, ((ulong)(uint)width << 32) | (uint)height);
                AttrPtr.SetUInt64(inType, Mf.MtFrameRate, ((ulong)(uint)fps << 32) | 1u);
                AttrPtr.SetUInt64(inType, Mf.MtPixelAspectRatio, (1UL << 32) | 1u);
                AttrPtr.SetUInt32(inType, Mf.MtInterlaceMode, 2);
                // Output-first is the encoder convention, but some
                // MFTs only negotiate after the input type exists:
                // try output -> input, then input -> output, and
                // report the last refusal by name.
                var outHr = TransformPtr.SetOutputType(_mftPtr, 0, outType, 0);
                if (Mf.Ok(outHr))
                {
                    var inHr = TransformPtr.SetInputType(_mftPtr, 0, inType, 0);
                    if (!Mf.Ok(inHr)) { error = $"encoder SetInputType(NV12) {Mf.Hr(inHr)}"; return false; }
                }
                else
                {
                    var inHr = TransformPtr.SetInputType(_mftPtr, 0, inType, 0);
                    if (!Mf.Ok(inHr)) { error = $"encoder SetOutputType(H264) {Mf.Hr(outHr)}; SetInputType(NV12) {Mf.Hr(inHr)}"; return false; }
                    var outHr2 = TransformPtr.SetOutputType(_mftPtr, 0, outType, 0);
                    if (!Mf.Ok(outHr2)) { error = $"encoder SetOutputType(H264) after input {Mf.Hr(outHr2)}"; return false; }
                }
            }
            finally { Marshal.Release(inType); }
        }
        finally { Marshal.Release(outType); }

        SetCodecBool(Mf.CodecApiLowLatency, true);
        mft.ProcessMessage(Mf.MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, IntPtr.Zero);
        mft.ProcessMessage(Mf.MFT_MESSAGE_NOTIFY_START_OF_STREAM, IntPtr.Zero);
        return true;
    }

    /// <summary>Ask the encoder to make the NEXT frame an IDR.
    /// Best-effort by design: the frame header's keyframe flag is
    /// derived from the actual NAL units produced, never from this
    /// request, so a refused request degrades cadence, not truth.</summary>
    public void RequestKeyFrame()
    {
        if (_codecApi is null) return;
        var variant = Marshal.AllocHGlobal(24);
        try
        {
            for (var i = 0; i < 24; i++) Marshal.WriteByte(variant, i, 0);
            Marshal.WriteInt16(variant, 0, 11); // VT_BOOL
            Marshal.WriteInt16(variant, 8, -1); // VARIANT_TRUE
            _codecApi.SetValue(Mf.CodecApiForceKeyFrame, variant);
        }
        finally { Marshal.FreeHGlobal(variant); }
    }

    private void SetCodecBool(Guid api, bool value)
    {
        if (_codecApi is null) return;
        var variant = Marshal.AllocHGlobal(24);
        try
        {
            for (var i = 0; i < 24; i++) Marshal.WriteByte(variant, i, 0);
            Marshal.WriteInt16(variant, 0, 11);
            Marshal.WriteInt16(variant, 8, (short)(value ? -1 : 0));
            _codecApi.SetValue(api, variant);
        }
        finally { Marshal.FreeHGlobal(variant); }
    }

    /// <summary>Encode one NV12 frame; returns every AU produced
    /// (usually 0 or 1; an async hardware MFT may lag a frame, which
    /// the caller absorbs — latency stats stay honest because each
    /// AU carries its own capture timestamp from the caller).</summary>
    public unsafe IReadOnlyList<EncodedAu> Encode(ReadOnlySpan<byte> nv12, long time100ns, long duration100ns)
    {
        var results = new List<EncodedAu>();
        var mft = _mft;
        if (mft is null) return results;
        var expected = Width * Height * 3 / 2;
        if (nv12.Length < expected) return results;
        if (!Mf.Ok(Mf.MFCreateMemoryBuffer(expected, out var inBuffer))) return results;
        var inSample = IntPtr.Zero;
        try
        {
            if (!Mf.Ok(BufferPtr.Lock(inBuffer, out var dst, out _, out _))) return results;
            nv12.Slice(0, expected).CopyTo(new Span<byte>((void*)dst, expected));
            BufferPtr.Unlock(inBuffer);
            BufferPtr.SetCurrentLength(inBuffer, expected);
            if (!Mf.Ok(Mf.MFCreateSample(out inSample))) return results;
            SamplePtr.AddBuffer(inSample, inBuffer);
            SamplePtr.SetSampleTime(inSample, time100ns);
            SamplePtr.SetSampleDuration(inSample, duration100ns);
            var hr = TransformPtr.ProcessInput(_mftPtr, 0, inSample, 0);
            if (hr == unchecked((int)0xC00D36B5)) // MF_E_NOTACCEPTING
            {
                // BD-WIN-AGENT F12: drain and RETRY THE SAME SAMPLE
                // once. The pre-fix code dropped the frame on the
                // floor ("retry once next call" — with a different
                // frame), losing it whenever an async MFT lagged.
                Drain(results, mft);
                hr = TransformPtr.ProcessInput(_mftPtr, 0, inSample, 0);
            }
            if (!Mf.Ok(hr) && hr != unchecked((int)0xC00D36B5))
                return results;
            Drain(results, mft);
            return results;
        }
        finally
        {
            if (inSample != IntPtr.Zero) Marshal.Release(inSample);
            Marshal.Release(inBuffer);
        }
    }

    private void Drain(List<EncodedAu> results, IMFTransform mft)
    {
        for (var guard = 0; guard < 8; guard++)
        {
            var hr = mft.GetOutputStreamInfo(0, out var info);
            if (!Mf.Ok(hr)) return;
            var providesSamples = (info.Flags & Mf.MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0;
            var outSample = IntPtr.Zero;
            var samplePtr = IntPtr.Zero;
            if (!providesSamples)
            {
                var size = Math.Max(info.CbSize, 64 * 1024);
                if (!Mf.Ok(Mf.MFCreateMemoryBuffer(size, out var outBuffer))) return;
                if (!Mf.Ok(Mf.MFCreateSample(out outSample))) { Marshal.Release(outBuffer); return; }
                SamplePtr.AddBuffer(outSample, outBuffer);
                Marshal.Release(outBuffer);
                samplePtr = outSample;
            }
            var buffers = new[] { new Mf.MftOutputDataBuffer { StreamID = 0, Sample = samplePtr, Status = 0, Events = IntPtr.Zero } };
            hr = mft.ProcessOutput(0, 1, buffers, out _);
            if (hr == Mf.MF_E_TRANSFORM_NEED_MORE_INPUT)
            {
                if (outSample != IntPtr.Zero) Marshal.Release(outSample);
                return;
            }
            if (hr == Mf.MF_E_TRANSFORM_STREAM_CHANGE)
            {
                // The encoder picked its real output type (SPS lives
                // here on some MFTs): accept it and retry the drain.
                if (outSample != IntPtr.Zero) { Marshal.Release(outSample); outSample = IntPtr.Zero; }
                if (Mf.Ok(TransformPtr.GetOutputCurrentType(_mftPtr, 0, out var current)) && current != IntPtr.Zero)
                {
                    TransformPtr.SetOutputType(_mftPtr, 0, current, 0);
                    Marshal.Release(current);
                }
                continue;
            }
            if (!Mf.Ok(hr))
            {
                if (outSample != IntPtr.Zero) Marshal.Release(outSample);
                return;
            }
            var sample = buffers[0].Sample;
            if (sample != IntPtr.Zero &&
                Mf.Ok(SamplePtr.ConvertToContiguousBuffer(sample, out var contiguous)) && contiguous != IntPtr.Zero)
            {
                if (Mf.Ok(BufferPtr.Lock(contiguous, out var src, out _, out var length)) && length > 0)
                {
                    var data = new byte[length];
                    Marshal.Copy(src, data, 0, length);
                    BufferPtr.Unlock(contiguous);
                    var types = Acp.Shared.Streaming.H264.NalTypes(data);
                    results.Add(new EncodedAu(data, types.Contains(5)));
                }
                Marshal.Release(contiguous);
            }
            if (buffers[0].Events != IntPtr.Zero) Marshal.Release(buffers[0].Events);
            if (providesSamples && buffers[0].Sample != IntPtr.Zero) Marshal.Release(buffers[0].Sample);
            if (outSample != IntPtr.Zero) Marshal.Release(outSample);
        }
    }

    public void Dispose()
    {
        try { _mft?.ProcessMessage(Mf.MFT_MESSAGE_COMMAND_FLUSH, IntPtr.Zero); } catch { }
        _mft = null;
        _mftPtr = IntPtr.Zero; // borrowed pointer: the RCW owns the reference
        _codecApi = null;
        // BD-WIN-AGENT F12: balance the MF startup this encoder held.
        if (_holdsMf) { _holdsMf = false; MfLifetime.Release(); }
    }
}

/// <summary>Media Foundation H.264 decoder wrapper for the Windows
/// operator viewer: Annex B in, BGRA out (NV12 → BGRA on the CPU —
/// viewer-side cost, named, not hidden).</summary>
internal sealed class H264Decoder : IDisposable
{
    private IMFTransform? _mft;
    private IntPtr _mftPtr;
    private int _width, _height;
    private bool _outputSet;

    public static bool TryCreate(out H264Decoder? decoder, out string error)
    {
        decoder = null;
        var hr = Mf.MFStartup(Mf.MF_VERSION, Mf.MFSTARTUP_LITE);
        if (!Mf.Ok(hr)) { error = $"MFStartup failed {Mf.Hr(hr)}"; return false; }
        var input = new Mf.MftRegisterTypeInfo { GuidMajorType = Mf.MediaTypeVideo, GuidSubtype = Mf.FormatH264 };
        var output = new Mf.MftRegisterTypeInfo { GuidMajorType = Mf.MediaTypeVideo, GuidSubtype = Mf.FormatNV12 };
        hr = Mf.MFTEnumEx(Mf.CategoryVideoDecoder,
            Mf.MFT_ENUM_FLAG_SYNCMFT | Mf.MFT_ENUM_FLAG_ASYNCMFT | Mf.MFT_ENUM_FLAG_SORTANDFILTER,
            input, output, out var activates, out var count);
        if (!Mf.Ok(hr) || count == 0 || activates == IntPtr.Zero)
        {
            error = $"no H.264 decoder MFT (enum {(Mf.Ok(hr) ? "empty" : Mf.Hr(hr))})";
            if (activates != IntPtr.Zero) Marshal.FreeCoTaskMem(activates);
            return false;
        }
        var dec = new H264Decoder();
        try
        {
            for (var i = 0; i < count; i++)
            {
                var activate = Marshal.ReadIntPtr(activates, i * IntPtr.Size);
                if (Mf.Ok(ActivateHelper.ActivateTransform(activate, out var mft, out var mftPtrRaw)) && mft is not null)
                {
                    dec._mft = mft;
                    dec._mftPtr = mftPtrRaw; // borrowed raw interface pointer (never Released)
                    break;
                }
            }
        }
        finally
        {
            for (var i = 0; i < count; i++)
            {
                var activate = Marshal.ReadIntPtr(activates, i * IntPtr.Size);
                if (activate != IntPtr.Zero) Marshal.Release(activate);
            }
            Marshal.FreeCoTaskMem(activates);
        }
        if (dec._mft is null) { error = "no enumerated H.264 decoder would activate"; return false; }
        // Input type: H.264, dimensions unknown until the first AU's
        // SPS — set a permissive type now, fix on STREAM_CHANGE.
        if (!Mf.Ok(Mf.MFCreateMediaType(out var inType))) { error = "MFCreateMediaType(dec-in) failed"; dec.Dispose(); return false; }
        try
        {
            AttrPtr.SetGUID(inType, Mf.MtMajorType, Mf.MediaTypeVideo);
            AttrPtr.SetGUID(inType, Mf.MtSubtype, Mf.FormatH264);
            hr = TransformPtr.SetInputType(dec._mftPtr, 0, inType, 0);
            if (!Mf.Ok(hr)) { error = $"decoder SetInputType {Mf.Hr(hr)}"; dec.Dispose(); return false; }
        }
        finally { Marshal.Release(inType); }
        dec._mft.ProcessMessage(Mf.MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, IntPtr.Zero);
        dec._mft.ProcessMessage(Mf.MFT_MESSAGE_NOTIFY_START_OF_STREAM, IntPtr.Zero);
        decoder = dec;
        error = "";
        return true;
    }

    /// <summary>Decode one AU; returns BGRA bytes + size when a
    /// frame emerges, else null (decoder is buffering — normal for
    /// the first AUs).</summary>
    public unsafe (byte[] Bgra, int Width, int Height)? Decode(ReadOnlySpan<byte> au)
    {
        var mft = _mft;
        if (mft is null || au.Length == 0) return null;
        if (!Mf.Ok(Mf.MFCreateMemoryBuffer(au.Length, out var inBuffer))) return null;
        var inSample = IntPtr.Zero;
        try
        {
            if (!Mf.Ok(BufferPtr.Lock(inBuffer, out var dst, out _, out _))) return null;
            au.CopyTo(new Span<byte>((void*)dst, au.Length));
            BufferPtr.Unlock(inBuffer);
            BufferPtr.SetCurrentLength(inBuffer, au.Length);
            if (!Mf.Ok(Mf.MFCreateSample(out inSample))) return null;
            SamplePtr.AddBuffer(inSample, inBuffer);
            var hr = TransformPtr.ProcessInput(_mftPtr, 0, inSample, 0);
            if (!Mf.Ok(hr) && hr != unchecked((int)0xC00D36B5)) return null;
        }
        finally
        {
            if (inSample != IntPtr.Zero) Marshal.Release(inSample);
            Marshal.Release(inBuffer);
        }
        for (var guard = 0; guard < 4; guard++)
        {
            if (!_outputSet)
            {
                // Pick the first NV12 output type the decoder offers.
                for (var i = 0; ; i++)
                {
                    var hr2 = TransformPtr.GetOutputAvailableType(_mftPtr, 0, i, out var avail);
                    if (!Mf.Ok(hr2) || avail == IntPtr.Zero) break;
                    try
                    {
                        if (Mf.Ok(AttrPtr.GetGUID(avail, Mf.MtSubtype, out var sub)) && sub == Mf.FormatNV12)
                        {
                            if (Mf.Ok(AttrPtr.GetUInt64(avail, Mf.MtFrameSize, out var fs)))
                            {
                                _width = (int)(fs >> 32); _height = (int)(fs & 0xFFFFFFFF);
                            }
                            TransformPtr.SetOutputType(_mftPtr, 0, avail, 0);
                            _outputSet = true;
                            break;
                        }
                    }
                    finally { Marshal.Release(avail); }
                }
                if (!_outputSet) return null;
            }
            var hr = mft.GetOutputStreamInfo(0, out var info);
            if (!Mf.Ok(hr)) return null;
            var provides = (info.Flags & Mf.MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0;
            var outSample = IntPtr.Zero;
            var samplePtr = IntPtr.Zero;
            if (!provides)
            {
                var size = Math.Max(info.CbSize, _width * _height * 3 / 2);
                if (size <= 0) size = 1024 * 1024;
                if (!Mf.Ok(Mf.MFCreateMemoryBuffer(size, out var outBuffer))) return null;
                if (!Mf.Ok(Mf.MFCreateSample(out outSample))) { Marshal.Release(outBuffer); return null; }
                SamplePtr.AddBuffer(outSample, outBuffer);
                Marshal.Release(outBuffer);
                samplePtr = outSample;
            }
            var buffers = new[] { new Mf.MftOutputDataBuffer { StreamID = 0, Sample = samplePtr, Status = 0, Events = IntPtr.Zero } };
            hr = mft.ProcessOutput(0, 1, buffers, out _);
            if (hr == Mf.MF_E_TRANSFORM_NEED_MORE_INPUT)
            {
                if (outSample != IntPtr.Zero) Marshal.Release(outSample);
                return null;
            }
            if (hr == Mf.MF_E_TRANSFORM_STREAM_CHANGE)
            {
                _outputSet = false;
                if (outSample != IntPtr.Zero) { Marshal.Release(outSample); outSample = IntPtr.Zero; }
                if (Mf.Ok(TransformPtr.GetOutputCurrentType(_mftPtr, 0, out var current)) && current != IntPtr.Zero)
                {
                    if (Mf.Ok(AttrPtr.GetUInt64(current, Mf.MtFrameSize, out var fs)))
                    {
                        _width = (int)(fs >> 32); _height = (int)(fs & 0xFFFFFFFF);
                    }
                    Marshal.Release(current);
                }
                continue;
            }
            if (!Mf.Ok(hr))
            {
                if (outSample != IntPtr.Zero) Marshal.Release(outSample);
                return null;
            }
            var sample = buffers[0].Sample;
            (byte[] Bgra, int Width, int Height)? result = null;
            if (sample != IntPtr.Zero && _width > 0 && _height > 0 &&
                Mf.Ok(SamplePtr.ConvertToContiguousBuffer(sample, out var contiguous)) && contiguous != IntPtr.Zero)
            {
                if (Mf.Ok(BufferPtr.Lock(contiguous, out var src, out _, out var length)))
                {
                    var nv12 = new byte[length];
                    Marshal.Copy(src, nv12, 0, length);
                    BufferPtr.Unlock(contiguous);
                    result = (Nv12ToBgra(nv12, _width, _height), _width, _height);
                }
                Marshal.Release(contiguous);
            }
            if (buffers[0].Events != IntPtr.Zero) Marshal.Release(buffers[0].Events);
            if (provides && buffers[0].Sample != IntPtr.Zero) Marshal.Release(buffers[0].Sample);
            if (outSample != IntPtr.Zero) Marshal.Release(outSample);
            if (result is not null) return result;
            return null;
        }
        return null;
    }

    internal static byte[] Nv12ToBgra(ReadOnlySpan<byte> nv12, int width, int height)
    {
        var bgra = new byte[width * height * 4];
        var ySize = width * height;
        for (var y = 0; y < height; y++)
        {
            var yRow = y * width;
            var uvRow = ySize + (y / 2) * width;
            for (var x = 0; x < width; x++)
            {
                var yy = nv12[yRow + x] - 16;
                var uvIdx = uvRow + (x & ~1);
                var u = nv12[uvIdx] - 128;
                var v = nv12[uvIdx + 1] - 128;
                var c = Math.Max(yy, 0);
                var r = (298 * c + 409 * v + 128) >> 8;
                var g = (298 * c - 100 * u - 208 * v + 128) >> 8;
                var b = (298 * c + 516 * u + 128) >> 8;
                var p = (yRow + x) * 4;
                bgra[p] = (byte)Math.Clamp(b, 0, 255);
                bgra[p + 1] = (byte)Math.Clamp(g, 0, 255);
                bgra[p + 2] = (byte)Math.Clamp(r, 0, 255);
                bgra[p + 3] = 255;
            }
        }
        return bgra;
    }

    internal static byte[] BgraToNv12(ReadOnlySpan<byte> bgra, int width, int height, int stride)
    {
        var nv12 = new byte[width * height * 3 / 2];
        var ySize = width * height;
        for (var y = 0; y < height; y++)
        {
            var row = y * stride;
            for (var x = 0; x < width; x++)
            {
                var p = row + x * 4;
                var b = bgra[p]; var g = bgra[p + 1]; var r = bgra[p + 2];
                nv12[y * width + x] = (byte)Math.Clamp(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16, 0, 255);
                if ((y & 1) == 0 && (x & 1) == 0)
                {
                    var uv = ySize + (y / 2) * width + x;
                    nv12[uv] = (byte)Math.Clamp(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128, 0, 255);
                    nv12[uv + 1] = (byte)Math.Clamp(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128, 0, 255);
                }
            }
        }
        return nv12;
    }

    public void Dispose()
    {
        _mft = null;
        _mftPtr = IntPtr.Zero; // borrowed pointer: the RCW owns the reference
    }
}
