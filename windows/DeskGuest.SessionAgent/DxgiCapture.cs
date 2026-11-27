using System.Runtime.InteropServices;

namespace DeskGuest.SessionAgent;

/// <summary>One captured desktop frame (BGRA rows copied out of the
/// mapped desktop surface) + the damage rect the duplication API
/// reported for it (null = pointer-only or full-frame update).</summary>
internal sealed record CapturedFrame(byte[] Bgra, int Width, int Height, int Stride,
    DeskGuest.Shared.Streaming.StreamProtocol.DamageRect? Damage, bool Accumulated);

/// <summary>
/// DXGI Desktop Duplication capture (Block D) — the platform's own
/// damage-aware screen source. AcquireNextFrame reports which
/// rectangles changed (GetFrameDirtyRects); a timeout with no new
/// frame is the static-screen case and produces NOTHING (the caller
/// encodes nothing for it). Pixels are read through
/// MapDesktopSurface, so the path needs no ID3D11DeviceContext
/// calls at all. Failure modes are named, never hidden:
/// DXGI_ERROR_ACCESS_LOST (mode change / desktop switch) and
/// DXGI_ERROR_ACCESS_DENIED (the secure desktop — duplication is
/// refused there by the platform, which is exactly the protected-
/// surface behavior the stream inherits) end the capture with the
/// reason in the tool result.
///
/// COM discipline: every interface below declares its FULL vtable
/// prefix (IDXGIObject / ID3D11DeviceChild ancestors) in order —
/// a shortened declaration dispatches to the wrong slot and crashes
/// the host process, so the prefixes are written out, not elided.
/// </summary>
internal sealed class DxgiCapture : IDisposable
{
    private IntPtr _device;
    private IntPtr _duplication;

    public int Width { get; private set; }
    public int Height { get; private set; }
    public int OriginX { get; private set; }
    public int OriginY { get; private set; }
    public string? LastError { get; private set; }

    public const int ErrorAccessLost = unchecked((int)0x887A0026);
    public const int ErrorAccessDenied = unchecked((int)0x887A002B);
    public const int ErrorWaitTimeout = unchecked((int)0x887A0027);
    public const int ErrorSessionDisconnected = unchecked((int)0x887A0028);
    public const int ErrorUnsupported = unchecked((int)0x887A0004);

    public static IReadOnlyList<(int Index, int X, int Y, int W, int H, bool Primary)> EnumerateMonitors()
    {
        var result = new List<(int, int, int, int, int, bool)>();
        foreach (var s in System.Windows.Forms.Screen.AllScreens)
            result.Add((result.Count, s.Bounds.X, s.Bounds.Y, s.Bounds.Width, s.Bounds.Height, s.Primary));
        return result;
    }

    public bool Start(int monitorIndex)
    {
        // Contract: never throws. Any COM failure — including an
        // adapter whose QueryInterface refuses IDXGIAdapter1, seen
        // live on a hybrid-GPU laptop (AMD iGPU + NVIDIA dGPU),
        // 2026-11-19 — becomes LastError + false so the engine can
        // take its designed GDI fallback.
        try
        {
            return StartCore(monitorIndex);
        }
        catch (Exception ex)
        {
            LastError = ex is COMException com && com.ErrorCode == ErrorAccessDenied
                ? "Desktop Duplication refused: ACCESS_DENIED (secure desktop or protected session)"
                : $"DXGI capture unavailable ({ex.GetType().Name}): {ex.Message}";
            return false;
        }
    }

    private bool StartCore(int monitorIndex)
    {
        var hr = D3D11CreateDevice(IntPtr.Zero, 1 /*HARDWARE*/, IntPtr.Zero, 0x20 /*BGRA_SUPPORT*/,
            null, 0, 7, out _device, out _, out var context);
        if (context != IntPtr.Zero) Marshal.Release(context);
        if (hr < 0 || _device == IntPtr.Zero) { LastError = $"D3D11CreateDevice {Mf.Hr(hr)}"; return false; }
        hr = CreateDXGIFactory1(typeof(IDxgiFactory1).GUID, out var factoryPtr);
        if (hr < 0) { LastError = $"CreateDXGIFactory1 {Mf.Hr(hr)}"; return false; }
        var factory = (IDxgiFactory1)Marshal.GetObjectForIUnknown(factoryPtr);
        Marshal.Release(factoryPtr);
        // The stream's monitor index is the WinForms monitor index
        // (EnumerateMonitors). DXGI outputs are matched to it by
        // desktop geometry, never by positional counting: positional
        // counting picked a DETACHED port (empty desc, 0x0 size) on
        // the reference laptop and reported success, 2026-11-19.
        var monitors = EnumerateMonitors();
        if (monitorIndex < 0 || monitorIndex >= monitors.Count)
        {
            LastError = $"monitor index {monitorIndex} out of range ({monitors.Count} monitor(s))";
            return false;
        }
        var want = monitors[monitorIndex];
        string? firstAdapterError = null;
        for (uint a = 0; ; a++)
        {
            IDxgiAdapter1 adapter;
            try
            {
                if (factory.EnumAdapters1(a, out var adapterPtr) < 0 || adapterPtr == IntPtr.Zero) break;
                adapter = (IDxgiAdapter1)Marshal.GetObjectForIUnknown(adapterPtr);
                Marshal.Release(adapterPtr);
            }
            catch (Exception ex)
            {
                // One adapter refusing the cast must not kill the
                // walk: a later adapter may own the target output.
                firstAdapterError ??= $"adapter {a}: ({ex.GetType().Name}) {ex.Message}";
                continue;
            }
            for (uint o = 0; ; o++)
            {
                if (adapter.EnumOutputs(o, out var outputPtr) < 0 || outputPtr == IntPtr.Zero) break;
                var output = (IDxgiOutput)Marshal.GetObjectForIUnknown(outputPtr);
                Marshal.Release(outputPtr);
                output.GetDesc(out var desc);
                var ow = desc.DesktopCoordinates.Right - desc.DesktopCoordinates.Left;
                var oh = desc.DesktopCoordinates.Bottom - desc.DesktopCoordinates.Top;
                if (desc.AttachedToDesktop == 0 || ow <= 0 || oh <= 0) continue;
                if (desc.DesktopCoordinates.Left != want.X || desc.DesktopCoordinates.Top != want.Y || ow != want.W || oh != want.H) continue;
                Width = ow;
                Height = oh;
                OriginX = desc.DesktopCoordinates.Left;
                OriginY = desc.DesktopCoordinates.Top;
                var output1 = (IDxgiOutput1)Marshal.GetObjectForIUnknown(Marshal.GetIUnknownForObject(output));
                hr = output1.DuplicateOutput(_device, out _duplication);
                if (hr < 0 || _duplication == IntPtr.Zero)
                {
                    LastError = hr == ErrorAccessDenied
                        ? "Desktop Duplication refused: ACCESS_DENIED (secure desktop or protected session)"
                        : $"DuplicateOutput {Mf.Hr(hr)}";
                    return false;
                }
                return true;
            }
        }
        LastError = firstAdapterError is not null
            ? $"no attached DXGI output matches monitor {monitorIndex} ({want.W}x{want.H} at {want.X},{want.Y}) ({firstAdapterError})"
            : $"no attached DXGI output matches monitor {monitorIndex} ({want.W}x{want.H} at {want.X},{want.Y})";
        return false;
    }

    /// <summary>Acquire the next frame. Null (with LastError null)
    /// means "no new frame within the timeout" — the static case.
    /// Null with LastError set means the capture is over.</summary>
    public CapturedFrame? NextFrame(int timeoutMs)
    {
        LastError = null;
        if (_duplication == IntPtr.Zero) { LastError = "duplication not started"; return null; }
        var dup = (IDxgiOutputDuplication)Marshal.GetObjectForIUnknown(_duplication);
        var hr = dup.AcquireNextFrame(timeoutMs, out var info, out var resource);
        if (hr == ErrorWaitTimeout) return null;
        if (hr < 0 || resource == IntPtr.Zero)
        {
            LastError = hr switch
            {
                ErrorAccessLost => "ACCESS_LOST — desktop mode changed or the desktop switched (capture ended)",
                ErrorAccessDenied => "ACCESS_DENIED — the secure desktop cannot be duplicated (capture ended)",
                ErrorSessionDisconnected => "SESSION_DISCONNECTED — the session was disconnected (capture ended)",
                _ => $"AcquireNextFrame {Mf.Hr(hr)}",
            };
            return null;
        }
        try
        {
            // Damage: the dirty rects of THIS frame presentation.
            DeskGuest.Shared.Streaming.StreamProtocol.DamageRect? damage = null;
            dup.GetFrameDirtyRects(0, IntPtr.Zero, out var rectsSize);
            if (rectsSize > 0)
            {
                var buf = Marshal.AllocHGlobal(rectsSize);
                try
                {
                    if (dup.GetFrameDirtyRects(rectsSize, buf, out var filled) >= 0 && filled >= 16)
                    {
                        int minX = int.MaxValue, minY = int.MaxValue, maxX = int.MinValue, maxY = int.MinValue;
                        for (var p = buf; p.ToInt64() < buf.ToInt64() + filled; p += 16)
                        {
                            var l = Marshal.ReadInt32(p); var t = Marshal.ReadInt32(p, 4);
                            var r = Marshal.ReadInt32(p, 8); var b = Marshal.ReadInt32(p, 12);
                            minX = Math.Min(minX, l); minY = Math.Min(minY, t);
                            maxX = Math.Max(maxX, r); maxY = Math.Max(maxY, b);
                        }
                        if (maxX > minX && maxY > minY) damage = new(minX, minY, maxX - minX, maxY - minY);
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            // Pixels via the mapped desktop surface.
            hr = dup.MapDesktopSurface(out var mapped);
            if (hr < 0)
            {
                LastError = hr == ErrorUnsupported
                    ? "MapDesktopSurface UNSUPPORTED on this output (capture ended)"
                    : $"MapDesktopSurface {Mf.Hr(hr)}";
                return null;
            }
            try
            {
                var stride = Width * 4;
                var bgra = new byte[stride * Height];
                for (var y = 0; y < Height; y++)
                    Marshal.Copy(mapped.Bits + y * mapped.Pitch, bgra, y * stride, stride);
                return new CapturedFrame(bgra, Width, Height, stride, damage, info.AccumulatedFrames > 0);
            }
            finally { dup.UnMapDesktopSurface(); }
        }
        finally
        {
            try { dup.ReleaseFrame(); } catch { }
            if (resource != IntPtr.Zero) Marshal.Release(resource);
        }
    }

    public void Dispose()
    {
        if (_duplication != IntPtr.Zero) { Marshal.Release(_duplication); _duplication = IntPtr.Zero; }
        if (_device != IntPtr.Zero) { Marshal.Release(_device); _device = IntPtr.Zero; }
    }

    [DllImport("d3d11.dll")] private static extern int D3D11CreateDevice(IntPtr adapter, int driverType, IntPtr software, uint flags, [In] int[]? featureLevels, uint numLevels, uint sdkVersion, out IntPtr device, out int chosenLevel, out IntPtr context);
    [DllImport("dxgi.dll")] private static extern int CreateDXGIFactory1(in Guid riid, out IntPtr factory);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DxgiOutputDesc
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public char[] DeviceName;
        public NativeRect DesktopCoordinates;
        public int AttachedToDesktop;
        public int Rotation;
        public IntPtr Monitor;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NativeRect { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    public struct DxgiOutduplFrameInfo
    {
        public long LastPresentTime;
        public long LastMouseUpdateTime;
        public uint AccumulatedFrames;
        public int RectsCoalesced;
        public int ProtectedContentMaskedOut;
        public NativeRect PointerPosition;
        public uint TotalMetadataBufferSize;
        public uint PointerShapeBufferSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DxgiMappedRect
    {
        public int Pitch;
        public IntPtr Bits;
    }
}

// ---- Full-vtable COM declarations (prefixes included, in order) ----

[ComImport, Guid("770aae78-f26f-4dba-a829-253c83d1b387"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IDxgiFactory1
{
    // IDXGIObject
    [PreserveSig] int SetPrivateData(in Guid guid, uint size, IntPtr data);
    [PreserveSig] int SetPrivateDataInterface(in Guid guid, IntPtr data);
    [PreserveSig] int GetPrivateData(in Guid guid, ref uint size, IntPtr data);
    [PreserveSig] int GetParent(in Guid riid, out IntPtr parent);
    // IDXGIFactory
    [PreserveSig] int EnumAdapters(uint index, out IntPtr adapter);
    [PreserveSig] int MakeWindowAssociation(IntPtr hwnd, uint flags);
    [PreserveSig] int GetWindowAssociation(out IntPtr hwnd);
    [PreserveSig] int CreateSwapChain(IntPtr device, IntPtr desc, out IntPtr swapChain);
    [PreserveSig] int CreateSoftwareAdapter(IntPtr module, out IntPtr adapter);
    // IDXGIFactory1
    [PreserveSig] int EnumAdapters1(uint index, out IntPtr adapter);
    [PreserveSig] int IsCurrent();
}

[ComImport, Guid("29038f61-3839-4626-91fd-086879011a05"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IDxgiAdapter1
{
    // IDXGIObject
    [PreserveSig] int SetPrivateData(in Guid guid, uint size, IntPtr data);
    [PreserveSig] int SetPrivateDataInterface(in Guid guid, IntPtr data);
    [PreserveSig] int GetPrivateData(in Guid guid, ref uint size, IntPtr data);
    [PreserveSig] int GetParent(in Guid riid, out IntPtr parent);
    // IDXGIAdapter
    [PreserveSig] int EnumOutputs(uint index, out IntPtr output);
    [PreserveSig] int GetDesc(IntPtr desc);
    [PreserveSig] int CheckInterfaceSupport(in Guid iid, out long version);
    // IDXGIAdapter1
    [PreserveSig] int GetDesc1(IntPtr desc);
}

[ComImport, Guid("ae02eedb-c735-4690-8d52-5a8dc20213aa"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IDxgiOutput
{
    // IDXGIObject
    [PreserveSig] int SetPrivateData(in Guid guid, uint size, IntPtr data);
    [PreserveSig] int SetPrivateDataInterface(in Guid guid, IntPtr data);
    [PreserveSig] int GetPrivateData(in Guid guid, ref uint size, IntPtr data);
    [PreserveSig] int GetParent(in Guid riid, out IntPtr parent);
    // IDXGIDeviceSubObject
    [PreserveSig] int GetDevice(in Guid riid, out IntPtr device);
    // IDXGIOutput
    [PreserveSig] int GetDesc(out DxgiCapture.DxgiOutputDesc desc);
    [PreserveSig] int GetDisplayModeList(int format, uint flags, ref uint count, IntPtr modes);
    [PreserveSig] int FindClosestMatchingMode(IntPtr modeToMatch, IntPtr closestMatch, IntPtr concernedDevice);
    [PreserveSig] int WaitForVBlank();
    [PreserveSig] int TakeOwnership(IntPtr device, int exclusive);
    [PreserveSig] void ReleaseOwnership();
    [PreserveSig] int GetGammaControlCapabilities(IntPtr caps);
    [PreserveSig] int SetGammaControl(IntPtr gamma);
    [PreserveSig] int SetDisplaySurface(IntPtr surface);
    [PreserveSig] int GetDisplaySurfaceData(IntPtr dest);
    [PreserveSig] int GetFrameStatistics(IntPtr stats);
}

[ComImport, Guid("00cddea8-939b-4b83-a340-a685226666cc"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IDxgiOutput1
{
    // IDXGIObject
    [PreserveSig] int SetPrivateData(in Guid guid, uint size, IntPtr data);
    [PreserveSig] int SetPrivateDataInterface(in Guid guid, IntPtr data);
    [PreserveSig] int GetPrivateData(in Guid guid, ref uint size, IntPtr data);
    [PreserveSig] int GetParent(in Guid riid, out IntPtr parent);
    // IDXGIDeviceSubObject
    [PreserveSig] int GetDevice(in Guid riid, out IntPtr device);
    // IDXGIOutput
    [PreserveSig] int GetDesc(out DxgiCapture.DxgiOutputDesc desc);
    [PreserveSig] int GetDisplayModeList(int format, uint flags, ref uint count, IntPtr modes);
    [PreserveSig] int FindClosestMatchingMode(IntPtr modeToMatch, IntPtr closestMatch, IntPtr concernedDevice);
    [PreserveSig] int WaitForVBlank();
    [PreserveSig] int TakeOwnership(IntPtr device, int exclusive);
    [PreserveSig] void ReleaseOwnership();
    [PreserveSig] int GetGammaControlCapabilities(IntPtr caps);
    [PreserveSig] int SetGammaControl(IntPtr gamma);
    [PreserveSig] int SetDisplaySurface(IntPtr surface);
    [PreserveSig] int GetDisplaySurfaceData(IntPtr dest);
    [PreserveSig] int GetFrameStatistics(IntPtr stats);
    // IDXGIOutput1
    [PreserveSig] int GetDisplayModeList1(int format, uint flags, ref uint count, IntPtr modes);
    [PreserveSig] int FindClosestMatchingMode1(IntPtr modeToMatch, IntPtr closestMatch, IntPtr concernedDevice);
    [PreserveSig] int GetDisplaySurfaceData1(IntPtr resource);
    [PreserveSig] int DuplicateOutput(IntPtr device, out IntPtr duplication);
}

[ComImport, Guid("191cfac3-a341-470d-b26e-a26f79d83e80"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IDxgiOutputDuplication
{
    // IDXGIObject
    [PreserveSig] int SetPrivateData(in Guid guid, uint size, IntPtr data);
    [PreserveSig] int SetPrivateDataInterface(in Guid guid, IntPtr data);
    [PreserveSig] int GetPrivateData(in Guid guid, ref uint size, IntPtr data);
    [PreserveSig] int GetParent(in Guid riid, out IntPtr parent);
    // IDXGIDeviceSubObject
    [PreserveSig] int GetDevice(in Guid riid, out IntPtr device);
    // IDXGIOutputDuplication
    [PreserveSig] int GetDesc(IntPtr desc);
    [PreserveSig] int AcquireNextFrame(int timeoutMs, out DxgiCapture.DxgiOutduplFrameInfo info, out IntPtr resource);
    [PreserveSig] int GetFrameDirtyRects(int bufferSize, IntPtr rects, out int bufferSizeRequired);
    [PreserveSig] int GetFrameMoveRects(int bufferSize, IntPtr rects, out int bufferSizeRequired);
    [PreserveSig] int GetFramePointerShape(int bufferSize, IntPtr shape, out int bufferSizeRequired, IntPtr shapeInfo);
    [PreserveSig] int MapDesktopSurface(out DxgiCapture.DxgiMappedRect lockedRect);
    [PreserveSig] int UnMapDesktopSurface();
    [PreserveSig] int ReleaseFrame();
}
