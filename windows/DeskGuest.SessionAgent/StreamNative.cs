using System.Runtime.InteropServices;

namespace DeskGuest.SessionAgent;

/// <summary>
/// Media Foundation interop for the session stream (Block D) —
/// PLATFORM components only (mfplat/mf/ole32, in-box + driver
/// hardware MFTs). No third-party codec code is adopted: the H.264
/// encoder is whatever Media Foundation enumerates on the machine
/// (hardware MFTs first — NVENC/AMF/QuickSync class — the in-box
/// Microsoft encoder as the software fallback), and the engine
/// reports which one it actually activated, by enumeration path.
///
/// GUID provenance: MFT category GUIDs are the Windows SDK mfapi.h
/// values (MFT_CATEGORY_VIDEO_ENCODER F79EAC7D-E545-4387-BDEE-
/// D647D7BDE42A; VIDEO_DECODER D6C02D4B-6833-45B4-971A-05A4B04BAB91);
/// media-type/attribute GUIDs are the mfobjects.h/mfapi.h SDK
/// values. Every call's HRESULT is checked by the wrappers in
/// H264Codec and surfaced in the stream_start tool result, so a
/// wrong constant fails loudly at start, never silently mid-stream.
/// </summary>
internal static class Mf
{
    public const int MF_VERSION = 0x0002_0070; // MF_SDK_VERSION<<16 | MF_API_VERSION
    public const uint MFSTARTUP_LITE = 1;

    [DllImport("mfplat.dll")] public static extern int MFStartup(int version, uint flags);
    [DllImport("mfplat.dll")] public static extern int MFShutdown();
    [DllImport("mfplat.dll")] public static extern int MFCreateMediaType(out IntPtr type);
    [DllImport("mfplat.dll")] public static extern int MFCreateSample(out IntPtr sample);
    [DllImport("mfplat.dll")] public static extern int MFCreateMemoryBuffer(int maxLength, out IntPtr buffer);
    [DllImport("mfplat.dll")] public static extern int MFCreateAttributes(out IntPtr attrs, int initialSize);
    [DllImport("mfplat.dll")] public static extern int MFTEnumEx(Guid category, uint flags, in MftRegisterTypeInfo input, in MftRegisterTypeInfo output, out IntPtr activates, out int count);
    [DllImport("ole32.dll")] public static extern int CoCreateInstance(in Guid clsid, IntPtr outer, uint clsContext, in Guid iid, out IntPtr obj);

    public const uint MFT_ENUM_FLAG_SYNCMFT = 0x00000001;
    public const uint MFT_ENUM_FLAG_ASYNCMFT = 0x00000002;
    public const uint MFT_ENUM_FLAG_HARDWARE = 0x00000004;
    public const uint MFT_ENUM_FLAG_SORTANDFILTER = 0x00000040;
    public const uint MFT_ENUM_FLAG_ALL = 0x0000000F; // SYNC|ASYNC|HARDWARE|LOCAL(by-CLSID excluded)

    public static readonly Guid CategoryVideoEncoder = new("f79eac7d-e545-4387-bdee-d647d7bde42a");
    public static readonly Guid CategoryVideoDecoder = new("d6c02d4b-6833-45b4-971a-05a4b04bab91");
    public static readonly Guid MediaTypeVideo = new("73646976-0000-0010-8000-00aa00389b71");
    public static readonly Guid FormatH264 = new("34363248-0000-0010-8000-00aa00389b71");
    public static readonly Guid FormatNV12 = new("3231564e-0000-0010-8000-00aa00389b71");
    public static readonly Guid FormatRGB32 = new("00000016-0000-0010-8000-00aa00389b71");
    public static readonly Guid FormatARGB32 = new("00000015-0000-0010-8000-00aa00389b71");

    public static readonly Guid MtMajorType = new("48eba18e-f8c5-4c69-aa98-3776007ecaf9");
    public static readonly Guid MtSubtype = new("f7e34c9a-42e8-4714-b74b-cb29d72c35e5");
    public static readonly Guid MtFrameSize = new("1652c33d-d6b2-4012-b834-308308dd9d72");
    public static readonly Guid MtFrameRate = new("c459a2e8-3d2c-4e44-b132-fee5156c7bb0");
    public static readonly Guid MtPixelAspectRatio = new("c6376a1e-8d0a-4027-be45-6d9a0ad39bb6");
    public static readonly Guid MtInterlaceMode = new("e2724bb8-e676-4806-b4b2-a7d6c7fd4cd4");
    public static readonly Guid MtAvgBitrate = new("20332624-fb0d-4d9e-bd45-67c678b61de7");
    public static readonly Guid MtAllSamplesIndependent = new("c9173739-5e56-461c-b713-46fb995cb95e");
    public static readonly Guid LowLatency = new("9c27891a-ed7a-40e1-88e8-b22727a024ee");
    public static readonly Guid TransformAsyncUnlock = new("e5666d6b-3422-4eb6-a421-da7db1f8e207");
    public static readonly Guid CodecApiForceKeyFrame = new("a9db058f-0edc-4bc8-8fd0-c8f1816d7d87"); // CODECAPI_AVEncVideoForceKeyFrame
    public static readonly Guid CodecApiLowLatency = new("9c27891a-ed7a-40e1-88e8-b22727a024ee"); // CODECAPI_AVLowLatencyMode shares MF_LOW_LATENCY's GUID family value in codecapi.h

    public static bool Ok(int hr) => hr >= 0;
    public static string Hr(int hr) => $"0x{hr:X8}";

    [StructLayout(LayoutKind.Sequential)]
    public struct MftRegisterTypeInfo
    {
        public Guid GuidMajorType;
        public Guid GuidSubtype;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MftOutputDataBuffer
    {
        public int StreamID;
        public IntPtr Sample; // IMFSample*
        public int Status;
        public IntPtr Events; // IMFCollection*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MftOutputStreamInfo
    {
        public uint Flags;
        public int CbSize;
        public int CbAlignment;
    }

    public const int MF_E_TRANSFORM_NEED_MORE_INPUT = unchecked((int)0xC00D6D72);
    public const int MF_E_TRANSFORM_STREAM_CHANGE = unchecked((int)0xC00D6D61);
    public const uint MFT_OUTPUT_STREAM_PROVIDES_SAMPLES = 0x100;

    public const int MFT_MESSAGE_NOTIFY_BEGIN_STREAMING = 0x10000000;
    public const int MFT_MESSAGE_NOTIFY_START_OF_STREAM = 0x10000002;
    public const int MFT_MESSAGE_COMMAND_FLUSH = 0x0;
    public const int MFT_MESSAGE_COMMAND_DRAIN = 0x1;
}

[ComImport, Guid("1c58a709-9b41-45e9-8c80-2e5dc06c7358"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMFAttributes
{
    [PreserveSig] int GetItem(in Guid key, IntPtr value);
    [PreserveSig] int GetItemType(in Guid key, out int type);
    [PreserveSig] int CompareItem(in Guid key, IntPtr value, out bool result);
    [PreserveSig] int Compare(IMFAttributes theirs, int matchType, out bool result);
    [PreserveSig] int GetUINT32(in Guid key, out uint value);
    [PreserveSig] int GetUINT64(in Guid key, out ulong value);
    [PreserveSig] int GetDouble(in Guid key, out double value);
    [PreserveSig] int GetGUID(in Guid key, out Guid value);
    [PreserveSig] int GetStringLength(in Guid key, out int length);
    [PreserveSig] int GetString(in Guid key, [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder value, int size, out int length);
    [PreserveSig] int GetAllocatedString(in Guid key, out IntPtr value, out int length);
    [PreserveSig] int GetBlobSize(in Guid key, out int size);
    [PreserveSig] int GetBlob(in Guid key, IntPtr buf, int size, out int blobSize);
    [PreserveSig] int GetAllocatedBlob(in Guid key, out IntPtr buf, out int size);
    [PreserveSig] int GetUnknown(in Guid key, in Guid iid, out IntPtr obj);
    [PreserveSig] int SetItem(in Guid key, IntPtr value);
    [PreserveSig] int DeleteItem(in Guid key);
    [PreserveSig] int DeleteAllItems();
    [PreserveSig] int SetUINT32(in Guid key, uint value);
    [PreserveSig] int SetUINT64(in Guid key, ulong value);
    [PreserveSig] int SetDouble(in Guid key, double value);
    [PreserveSig] int SetGUID(in Guid key, in Guid value);
    [PreserveSig] int SetString(in Guid key, [MarshalAs(UnmanagedType.LPWStr)] string value);
    [PreserveSig] int SetBlob(in Guid key, IntPtr buf, int size);
    [PreserveSig] int SetUnknown(in Guid key, [MarshalAs(UnmanagedType.IUnknown)] object obj);
    [PreserveSig] int LockStore();
    [PreserveSig] int UnlockStore();
    [PreserveSig] int GetCount(out int count);
    [PreserveSig] int GetItemByIndex(int index, out Guid key, IntPtr value);
    [PreserveSig] int CopyAllItems(IMFAttributes dest);
}

[ComImport, Guid("44ae0fa8-ea31-4109-8d2e-4cae4999c555"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMFMediaType : IMFAttributes
{
    [PreserveSig] int GetMajorType(out Guid guid);
    [PreserveSig] int IsCompressedFormat(out bool compressed);
    [PreserveSig] int IsEqual(IMFMediaType type, out uint flags);
    [PreserveSig] int GetRepresentation(int format, out IntPtr representation);
    [PreserveSig] int FreeRepresentation(int format, IntPtr representation);
}

[ComImport, Guid("045fa593-8799-42b8-bc8d-8968c6453507"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMFMediaBuffer
{
    [PreserveSig] int Lock(out IntPtr buffer, out int maxLength, out int currentLength);
    [PreserveSig] int Unlock();
    [PreserveSig] int GetCurrentLength(out int length);
    [PreserveSig] int SetCurrentLength(int length);
    [PreserveSig] int GetMaxLength(out int length);
}

[ComImport, Guid("c9bc716d-d9b5-4fc4-bffe-4125e9a5c31d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMFSample : IMFAttributes
{
    [PreserveSig] int GetSampleFlags(out uint flags);
    [PreserveSig] int SetSampleFlags(uint flags);
    [PreserveSig] int GetSampleTime(out long time);
    [PreserveSig] int SetSampleTime(long time);
    [PreserveSig] int GetSampleDuration(out long duration);
    [PreserveSig] int SetSampleDuration(long duration);
    [PreserveSig] int GetBufferCount(out int count);
    [PreserveSig] int GetBufferByIndex(int index, out IntPtr buffer);
    [PreserveSig] int ConvertToContiguousBuffer(out IntPtr buffer);
    [PreserveSig] int AddBuffer(IMFMediaBuffer buffer);
    [PreserveSig] int RemoveBufferByIndex(int index);
    [PreserveSig] int RemoveAllBuffers();
    [PreserveSig] int GetTotalLength(out int length);
    [PreserveSig] int CopyToBuffer(IMFMediaBuffer buffer);
}

[ComImport, Guid("bf94c121-5b05-4e6f-8000-ba598961414d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMFTransform
{
    [PreserveSig] int GetStreamLimits(out int minInput, out int maxInput, out int minOutput, out int maxOutput);
    [PreserveSig] int GetStreamCount(out int inputStreams, out int outputStreams);
    [PreserveSig] int GetStreamIDs(int inputSize, [Out] int[] inputIds, int outputSize, [Out] int[] outputIds);
    [PreserveSig] int GetInputStreamInfo(int inputStreamId, out MfInputStreamInfo info);
    [PreserveSig] int GetOutputStreamInfo(int outputStreamId, out Mf.MftOutputStreamInfo info);
    [PreserveSig] int GetAttributes(out IntPtr attributes);
    [PreserveSig] int GetInputStreamAttributes(int inputStreamId, out IntPtr attributes);
    [PreserveSig] int GetOutputStreamAttributes(int outputStreamId, out IntPtr attributes);
    [PreserveSig] int DeleteInputStream(int streamId);
    [PreserveSig] int AddInputStreams(int streams, [In] int[] streamIds);
    [PreserveSig] int GetInputAvailableType(int inputStreamId, int typeIndex, out IntPtr type);
    [PreserveSig] int GetOutputAvailableType(int outputStreamId, int typeIndex, out IntPtr type);
    [PreserveSig] int SetInputType(int inputStreamId, IMFMediaType type, uint flags);
    [PreserveSig] int SetOutputType(int outputStreamId, IMFMediaType type, uint flags);
    [PreserveSig] int GetInputCurrentType(int inputStreamId, out IntPtr type);
    [PreserveSig] int GetOutputCurrentType(int outputStreamId, out IntPtr type);
    [PreserveSig] int GetInputStatus(int inputStreamId, out uint flags);
    [PreserveSig] int GetOutputStatus(out uint flags);
    [PreserveSig] int SetOutputBounds(long lower, long upper);
    [PreserveSig] int ProcessEvent(int inputStreamId, IntPtr evnt);
    [PreserveSig] int ProcessMessage(int message, IntPtr param);
    [PreserveSig] int ProcessInput(int inputStreamId, IMFSample sample, uint flags);
    [PreserveSig] int ProcessOutput(uint flags, int bufferCount, [In, Out] Mf.MftOutputDataBuffer[] buffers, out int status);
}

[StructLayout(LayoutKind.Sequential)]
internal struct MfInputStreamInfo
{
    public long MaxLatency;
    public uint Flags;
    public int CbSize;
    public int CbMaxLookahead;
    public int CbAlignment;
    public Guid GuidMajorType;
    public Guid GuidSubtype;
}

/// <summary>IMFActivate is consumed through its raw vtable
/// (ActivateObject is slot 33: IUnknown 3 + IMFAttributes 30) so the
/// pipeline never depends on a typed-interface IID for it; the only
/// IID requested is IMFTransform's, which ActivateObject takes as a
/// parameter.</summary>
/// <summary>Raw-vtable accessors for the Media Foundation
/// attribute-family objects (IMFAttributes stores, IMFMediaType,
/// IMFSample, IMFMediaBuffer) and for the IMFTransform methods
/// whose signatures cross those interfaces. These objects are
/// driven by pointer + vtable slot ONLY — no QueryInterface, no
/// IID — because on the reference laptop (2026-11-19, probe-verified
/// against live objects) MFCreateAttributes / MFCreateMediaType /
/// an encoder MFT's attribute store all REFUSED QueryInterface
/// for the SDK-documented IMFAttributes / IMFMediaType IIDs with
/// E_NOINTERFACE, while their vtables served every call correctly
/// (GetCount/SetUInt32 round-trip proven). The pointers returned
/// by the MF factories and by GetAttributes ARE the interfaces;
/// the IID is never needed. Slot numbers follow the header
/// declaration order in mfobjects.h / mftransform.h, prefixes
/// included. IMFTransform itself is still consumed as an RCW: its
/// IID QueryInterfaces successfully (probe-verified), and its
/// value-only methods (GetOutputStreamInfo, ProcessMessage,
/// GetAttributes) marshal no interface pointers.</summary>
internal static class AttrPtr
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetUInt32Fn(IntPtr self, in Guid key, out uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetUInt64Fn(IntPtr self, in Guid key, out ulong value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetGuidFn(IntPtr self, in Guid key, out Guid value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetUInt32Fn(IntPtr self, in Guid key, uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetUInt64Fn(IntPtr self, in Guid key, ulong value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetGuidFn(IntPtr self, in Guid key, in Guid value);

    private static T Slot<T>(IntPtr obj, int slot) where T : Delegate
    {
        var vtbl = Marshal.ReadIntPtr(obj);
        return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(vtbl, slot * IntPtr.Size));
    }

    // IMFAttributes vtable: IUnknown 0-2, GetItem 3, GetItemType 4,
    // CompareItem 5, Compare 6, GetUINT32 7, GetUINT64 8,
    // GetDouble 9, GetGUID 10, ... SetUINT32 21, SetUINT64 22,
    // SetDouble 23, SetGUID 24.
    public static int GetUInt32(IntPtr attrs, Guid key, out uint value) => Slot<GetUInt32Fn>(attrs, 7)(attrs, key, out value);
    public static int GetUInt64(IntPtr attrs, Guid key, out ulong value) => Slot<GetUInt64Fn>(attrs, 8)(attrs, key, out value);
    public static int GetGUID(IntPtr attrs, Guid key, out Guid value) => Slot<GetGuidFn>(attrs, 10)(attrs, key, out value);
    public static int SetUInt32(IntPtr attrs, Guid key, uint value) => Slot<SetUInt32Fn>(attrs, 21)(attrs, key, value);
    public static int SetUInt64(IntPtr attrs, Guid key, ulong value) => Slot<SetUInt64Fn>(attrs, 22)(attrs, key, value);
    public static int SetGUID(IntPtr attrs, Guid key, Guid value) => Slot<SetGuidFn>(attrs, 24)(attrs, key, value);
}

/// <summary>IMFMediaBuffer by raw vtable: Lock 3, Unlock 4,
/// GetCurrentLength 5, SetCurrentLength 6, GetMaxLength 7.</summary>
internal static class BufferPtr
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int LockFn(IntPtr self, out IntPtr buffer, out int maxLength, out int currentLength);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int UnlockFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetCurrentLengthFn(IntPtr self, int length);

    private static T Slot<T>(IntPtr obj, int slot) where T : Delegate
    {
        var vtbl = Marshal.ReadIntPtr(obj);
        return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(vtbl, slot * IntPtr.Size));
    }

    public static int Lock(IntPtr buffer, out IntPtr ptr, out int maxLength, out int currentLength) =>
        Slot<LockFn>(buffer, 3)(buffer, out ptr, out maxLength, out currentLength);
    public static int Unlock(IntPtr buffer) => Slot<UnlockFn>(buffer, 4)(buffer);
    public static int SetCurrentLength(IntPtr buffer, int length) => Slot<SetCurrentLengthFn>(buffer, 6)(buffer, length);
}

/// <summary>IMFSample by raw vtable (IMFAttributes prefix 3-32,
/// then GetSampleFlags 33, SetSampleFlags 34, GetSampleTime 35,
/// SetSampleTime 36, GetSampleDuration 37, SetSampleDuration 38,
/// GetBufferCount 39, GetBufferByIndex 40,
/// ConvertToContiguousBuffer 41, AddBuffer 42).</summary>
internal static class SamplePtr
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetSampleTimeFn(IntPtr self, long time);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetSampleDurationFn(IntPtr self, long duration);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ConvertFn(IntPtr self, out IntPtr buffer);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int AddBufferFn(IntPtr self, IntPtr buffer);

    private static T Slot<T>(IntPtr obj, int slot) where T : Delegate
    {
        var vtbl = Marshal.ReadIntPtr(obj);
        return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(vtbl, slot * IntPtr.Size));
    }

    public static int SetSampleTime(IntPtr sample, long time) => Slot<SetSampleTimeFn>(sample, 36)(sample, time);
    public static int SetSampleDuration(IntPtr sample, long duration) => Slot<SetSampleDurationFn>(sample, 38)(sample, duration);
    public static int ConvertToContiguousBuffer(IntPtr sample, out IntPtr buffer) => Slot<ConvertFn>(sample, 41)(sample, out buffer);
    public static int AddBuffer(IntPtr sample, IntPtr buffer) => Slot<AddBufferFn>(sample, 42)(sample, buffer);
}

/// <summary>The IMFTransform methods whose signatures cross
/// attribute-family interface pointers, by raw vtable (prefix:
/// GetStreamLimits 3, GetStreamCount 4, GetStreamIDs 5,
/// GetInputStreamInfo 6, GetOutputStreamInfo 7, GetAttributes 8,
/// GetInputStreamAttributes 9, GetOutputStreamAttributes 10,
/// DeleteInputStream 11, AddInputStreams 12,
/// GetInputAvailableType 13, GetOutputAvailableType 14,
/// SetInputType 15, SetOutputType 16, GetInputCurrentType 17,
/// GetOutputCurrentType 18, GetInputStatus 19, GetOutputStatus
/// 20, SetOutputBounds 21, ProcessEvent 22, ProcessMessage 23,
/// ProcessInput 24, ProcessOutput 25).</summary>
internal static class TransformPtr
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetTypeFn(IntPtr self, int streamId, IntPtr type, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetTypeFn(IntPtr self, int streamId, int typeIndex, out IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetCurrentTypeFn(IntPtr self, int streamId, out IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ProcessInputFn(IntPtr self, int streamId, IntPtr sample, uint flags);

    private static T Slot<T>(IntPtr obj, int slot) where T : Delegate
    {
        var vtbl = Marshal.ReadIntPtr(obj);
        return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(vtbl, slot * IntPtr.Size));
    }

    public static int SetInputType(IntPtr mft, int streamId, IntPtr type, uint flags) => Slot<SetTypeFn>(mft, 15)(mft, streamId, type, flags);
    public static int SetOutputType(IntPtr mft, int streamId, IntPtr type, uint flags) => Slot<SetTypeFn>(mft, 16)(mft, streamId, type, flags);
    public static int GetOutputAvailableType(IntPtr mft, int streamId, int typeIndex, out IntPtr type) => Slot<GetTypeFn>(mft, 14)(mft, streamId, typeIndex, out type);
    public static int GetOutputCurrentType(IntPtr mft, int streamId, out IntPtr type) => Slot<GetCurrentTypeFn>(mft, 18)(mft, streamId, out type);
    public static int ProcessInput(IntPtr mft, int streamId, IntPtr sample, uint flags) => Slot<ProcessInputFn>(mft, 24)(mft, streamId, sample, flags);
}

internal static class ActivateHelper
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ActivateObjectDelegate(IntPtr self, in Guid iid, out IntPtr obj);

    public static int ActivateTransform(IntPtr activate, out IMFTransform? transform) =>
        ActivateTransform(activate, out transform, out _);

    /// <summary>As above, plus the RAW IMFTransform interface
    /// pointer exactly as ActivateObject returned it. Callers that
    /// drive the transform by raw vtable (TransformPtr) MUST use
    /// this pointer, never Marshal.GetIUnknownForObject(rcw): the
    /// canonical IUnknown of a multi-interface MFT is a different
    /// sub-object with a different vtable (probe-verified on
    /// the reference laptop, 2026-11-19 — raw calls through the canonical
    /// IUnknown produced E_POINTER / E_NOTIMPL / crashes at slots
    /// that are correct for IMFTransform). The pointer is a BORROW
    /// of the RCW's reference: valid while the RCW lives, never
    /// Release it.</summary>
    public static int ActivateTransform(IntPtr activate, out IMFTransform? transform, out IntPtr transformPtr)
    {
        transform = null;
        transformPtr = IntPtr.Zero;
        var vtable = Marshal.ReadIntPtr(activate);
        var fnPtr = Marshal.ReadIntPtr(vtable, 33 * IntPtr.Size);
        var fn = Marshal.GetDelegateForFunctionPointer<ActivateObjectDelegate>(fnPtr);
        var iid = typeof(IMFTransform).GUID;
        var hr = fn(activate, iid, out var obj);
        if (hr < 0 || obj == IntPtr.Zero) return hr < 0 ? hr : unchecked((int)0x80004005);
        transformPtr = obj;
        transform = (IMFTransform)Marshal.GetObjectForIUnknown(obj);
        Marshal.Release(obj);
        return 0;
    }
}

[ComImport, Guid("901db4c7-31ce-41a2-85dc-8fa0bf41b8da"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ICodecAPI
{
    [PreserveSig] int IsSupported(in Guid api);
    [PreserveSig] int IsModulated(in Guid api, out int modulated);
    [PreserveSig] int GetParameterRange(in Guid api, IntPtr min, IntPtr max, IntPtr step);
    [PreserveSig] int GetParameterValues(in Guid api, out IntPtr values, out int count);
    [PreserveSig] int GetDefaultValue(in Guid api, IntPtr value);
    [PreserveSig] int GetValue(in Guid api, IntPtr value);
    [PreserveSig] int SetValue(in Guid api, IntPtr value);
}
