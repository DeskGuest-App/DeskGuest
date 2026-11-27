using System.IO;
using System.Runtime.InteropServices;
using DeskGuest.Shared.Streaming;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The encode ladder's bottom rung: the bundled software encoder
/// (OpenH264 2.6.0, Cisco's BSD-licensed binary, shipped beside
/// the agent as openh264-2.6.0-win64.dll), driven through its C
/// ABI with zero Media Foundation involvement — the rung that
/// carries live sessions on machines whose MF stack is defective
/// (the reference laptop is the standing example: every MF H.264
/// MFT refuses constructed media types there, and Microsoft's own
/// SinkWriter control fails identically; DISM/SFC repair changed
/// nothing, 2026-11-25).
///
/// ABI discipline: every constant and offset comes from the 2.6.0
/// headers and is pinned in DeskGuest.Shared.Streaming.OpenH264Abi.
/// Three facts were earned the hard way by the conviction probe
/// (TEST 4, resolved 2026-11-25): InitializeExt accepts ONLY
/// usage types 0/1 (ParamValidationExt); the output AU is the
/// concatenation of EVERY SFrameBSInfo layer — the parameter
/// sets arrive in their own layer entry, ahead of the slices;
/// and WelsCreateSVCEncoder writes the encoder through an
/// out parameter (a pointer-returning model of it crashes).
///
/// Input is NV12 like every rung; this rung converts to padded
/// I420 (dimensions rounded up to a multiple of 16, edge pixels
/// replicated — see I420Conversion). The stream's frame headers
/// keep carrying the true capture dimensions and this rung's
/// name; nothing about the substitution is disguised.
/// </summary>
internal sealed class OpenH264Encoder : IH264StreamEncoder
{
    private readonly object _gate = new();
    private IntPtr _lib;
    private IntPtr _enc;
    private DestroyEncoderFn? _destroy;
    private int _paddedWidth, _paddedHeight;
    private bool _disposed;

    public bool Hardware => false;
    public string Description => "Bundled software H.264 encoder (OpenH264)";
    public int Width { get; private set; }
    public int Height { get; private set; }

    // codec_api.h: WelsCreateSVCEncoder(ISVCEncoder** ppEncoder)
    // returns a result code and writes the encoder through the
    // argument — the out-parameter model, proven against this DLL
    // by the conviction probe's TEST 4 (2026-11-25). Modelling it
    // as pointer-returning makes the callee write through a garbage
    // pointer: an access violation inside TryCreate, observed live
    // on the first proof run and corrected here.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CreateEncoderFn(out IntPtr encoder);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void DestroyEncoderFn(IntPtr encoder);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int InitializeExtFn(IntPtr self, IntPtr param);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int GetDefaultParamsFn(IntPtr self, IntPtr param);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int UninitializeFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int EncodeFrameFn(IntPtr self, IntPtr srcPic, IntPtr bsInfo);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ForceIntraFrameFn(IntPtr self, [MarshalAs(UnmanagedType.Bool)] bool idr, int layerId);

    private static T V<T>(IntPtr obj, int slot) where T : Delegate
    {
        var vtbl = Marshal.ReadIntPtr(obj);
        return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(vtbl, slot * IntPtr.Size));
    }

    private static void WI(IntPtr buf, int off, int v) => Marshal.WriteInt32(buf, off, v);
    private static void WF(IntPtr buf, int off, float v) =>
        Marshal.Copy(BitConverter.GetBytes(v), 0, buf + off, 4);

    public static bool TryCreate(int width, int height, int fps, int bitrateBps, out OpenH264Encoder? encoder, out string error)
    {
        encoder = null;
        error = "";
        var dllPath = Path.Combine(AppContext.BaseDirectory, OpenH264Abi.DllFileName);
        if (!File.Exists(dllPath)) { error = $"bundled encoder DLL not found at {dllPath}"; return false; }
        var enc = new OpenH264Encoder();
        try
        {
            enc._lib = NativeLibrary.Load(dllPath);
            var create = Marshal.GetDelegateForFunctionPointer<CreateEncoderFn>(
                NativeLibrary.GetExport(enc._lib, "WelsCreateSVCEncoder"));
            enc._destroy = Marshal.GetDelegateForFunctionPointer<DestroyEncoderFn>(
                NativeLibrary.GetExport(enc._lib, "WelsDestroySVCEncoder"));
            var createRc = create(out enc._enc);
            if (createRc != 0 || enc._enc == IntPtr.Zero) { error = $"WelsCreateSVCEncoder rc={createRc}"; enc.Dispose(); return false; }

            enc.Width = width; enc.Height = height;
            enc._paddedWidth = I420Conversion.PaddedDimension(width);
            enc._paddedHeight = I420Conversion.PaddedDimension(height);

            var param = Marshal.AllocHGlobal(OpenH264Abi.ParamBufferBytes);
            try
            {
                for (var i = 0; i < OpenH264Abi.ParamBufferBytes; i += 8) Marshal.WriteInt64(param, i, 0);
                var rc = V<GetDefaultParamsFn>(enc._enc, 2)(enc._enc, param);
                if (rc != 0) { error = $"OpenH264 GetDefaultParams rc={rc}"; enc.Dispose(); return false; }
                WI(param, OpenH264Abi.ParamUsageType, OpenH264Abi.UsageScreenContentRealTime);
                WI(param, OpenH264Abi.ParamPicWidth, enc._paddedWidth);
                WI(param, OpenH264Abi.ParamPicHeight, enc._paddedHeight);
                WI(param, OpenH264Abi.ParamTargetBitrate, bitrateBps);
                WI(param, OpenH264Abi.ParamRcMode, OpenH264Abi.RcBitrateMode);
                WF(param, OpenH264Abi.ParamMaxFrameRate, fps);
                WI(param, OpenH264Abi.ParamTemporalLayerNum, 1);
                WI(param, OpenH264Abi.ParamSpatialLayerNum, 1);
                WI(param, OpenH264Abi.LayerVideoWidth, enc._paddedWidth);
                WI(param, OpenH264Abi.LayerVideoHeight, enc._paddedHeight);
                WF(param, OpenH264Abi.LayerFrameRate, fps);
                WI(param, OpenH264Abi.LayerSpatialBitrate, bitrateBps);
                WI(param, OpenH264Abi.LayerMaxSpatialBitrate, bitrateBps);
                rc = V<InitializeExtFn>(enc._enc, 1)(enc._enc, param);
                if (rc != 0) { error = $"OpenH264 InitializeExt rc={rc}"; enc.Dispose(); return false; }
            }
            finally { Marshal.FreeHGlobal(param); }

            encoder = enc;
            return true;
        }
        catch (Exception ex)
        {
            error = $"OpenH264 load/init failed ({ex.GetType().Name}): {ex.Message}";
            enc.Dispose();
            return false;
        }
    }

    public void RequestKeyFrame()
    {
        lock (_gate)
        {
            if (_disposed || _enc == IntPtr.Zero) return;
            try { V<ForceIntraFrameFn>(_enc, 6)(_enc, true, -1); } catch { /* best-effort, like the MF rung: the AU's keyframe flag is read from its NALs, never from this request */ }
        }
    }

    public IReadOnlyList<EncodedAu> Encode(ReadOnlySpan<byte> nv12, long time100ns, long duration100ns)
    {
        lock (_gate)
        {
            if (_disposed || _enc == IntPtr.Zero) return Array.Empty<EncodedAu>();
            var expected = Width * Height * 3 / 2;
            if (nv12.Length < expected) return Array.Empty<EncodedAu>();
            var i420 = I420Conversion.Nv12ToI420Padded(nv12, Width, Height, _paddedWidth, _paddedHeight);
            var framePtr = Marshal.AllocHGlobal(i420.Length);
            var pic = Marshal.AllocHGlobal(OpenH264Abi.PicBufferBytes);
            var bs = Marshal.AllocHGlobal(OpenH264Abi.BsInfoBufferBytes);
            try
            {
                Marshal.Copy(i420, 0, framePtr, i420.Length);
                for (var i = 0; i < OpenH264Abi.BsInfoBufferBytes; i += 8) Marshal.WriteInt64(bs, i, 0);
                for (var i = 0; i < OpenH264Abi.PicBufferBytes; i += 8) Marshal.WriteInt64(pic, i, 0);
                var ySize = _paddedWidth * _paddedHeight;
                var cSize = (_paddedWidth / 2) * (_paddedHeight / 2);
                WI(pic, OpenH264Abi.PicColorFormat, OpenH264Abi.VideoFormatI420);
                WI(pic, OpenH264Abi.PicStride, _paddedWidth);
                WI(pic, OpenH264Abi.PicStride + 4, _paddedWidth / 2);
                WI(pic, OpenH264Abi.PicStride + 8, _paddedWidth / 2);
                Marshal.WriteIntPtr(pic, OpenH264Abi.PicData, framePtr);
                Marshal.WriteIntPtr(pic, OpenH264Abi.PicData + 8, framePtr + ySize);
                Marshal.WriteIntPtr(pic, OpenH264Abi.PicData + 16, framePtr + ySize + cSize);
                WI(pic, OpenH264Abi.PicWidth, _paddedWidth);
                WI(pic, OpenH264Abi.PicHeight, _paddedHeight);
                Marshal.WriteInt64(pic, OpenH264Abi.PicTimeStamp, time100ns / 10_000); // SSourcePicture timestamps are milliseconds

                var rc = V<EncodeFrameFn>(_enc, 4)(_enc, pic, bs);
                if (rc != 0) return Array.Empty<EncodedAu>();
                var layerNum = Marshal.ReadInt32(bs, 0);
                if (layerNum < 1) return Array.Empty<EncodedAu>(); // rate control skipped the frame
                var layers = new List<LayerBitstream>();
                for (var layer = 0; layer < layerNum; layer++)
                {
                    var lb = OpenH264Abi.LayerInfoOffset + layer * OpenH264Abi.LayerInfoSize;
                    var count = Marshal.ReadInt32(bs, lb + OpenH264Abi.LayerNalCount);
                    var lensPtr = Marshal.ReadIntPtr(bs, lb + OpenH264Abi.LayerNalLengths);
                    var bufPtr = Marshal.ReadIntPtr(bs, lb + OpenH264Abi.LayerBsBuf);
                    if (count < 1 || bufPtr == IntPtr.Zero || lensPtr == IntPtr.Zero) continue;
                    var lens = new int[count];
                    var total = 0;
                    for (var i = 0; i < count; i++) { lens[i] = Marshal.ReadInt32(lensPtr, i * 4); total += lens[i]; }
                    if (total <= 0) continue;
                    var data = new byte[total];
                    Marshal.Copy(bufPtr, data, 0, total);
                    layers.Add(new LayerBitstream(lens, data));
                }
                if (layers.Count == 0) return Array.Empty<EncodedAu>();
                var au = OpenH264Bitstream.ConcatAu(layers);
                if (au.Length == 0) return Array.Empty<EncodedAu>();
                var types = H264.NalTypes(au);
                return new[] { new EncodedAu(au, types.Contains(5)) };
            }
            catch
            {
                return Array.Empty<EncodedAu>();
            }
            finally
            {
                Marshal.FreeHGlobal(framePtr);
                Marshal.FreeHGlobal(pic);
                Marshal.FreeHGlobal(bs);
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try { if (_enc != IntPtr.Zero) V<UninitializeFn>(_enc, 3)(_enc); } catch { }
            try { if (_enc != IntPtr.Zero) _destroy?.Invoke(_enc); } catch { }
            _enc = IntPtr.Zero;
            try { if (_lib != IntPtr.Zero) NativeLibrary.Free(_lib); } catch { }
            _lib = IntPtr.Zero;
        }
    }
}
