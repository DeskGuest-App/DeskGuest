using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Text.Json;
using System.Windows.Forms;
using Acp.Shared.Streaming;

namespace Acp.SessionAgent;

/// <summary>
/// The stream capture+encode pump (Block D), living in the Session
/// Agent because capture belongs to the interactive session:
///
///   DXGI Desktop Duplication (damage rects from the platform)
///     → BGRA → NV12 → Media Foundation H.264 (hardware MFT first)
///     → Annex B access units in a small ring, served to the Core
///       through the stream_frame desktop tool.
///
/// Damage discipline: a DXGI timeout (nothing presented) or a GDI
/// diff with zero dirty tiles produces NO encode at all. The only
/// frames a static screen ever yields are keyframes on the keepalive
/// cadence (5 s), each forced + flagged from its real NAL content.
/// Motion frames target 30 fps; the pump never encodes faster than
/// the capture presents.
///
/// Fallback honesty: if Desktop Duplication cannot start (or dies
/// with ACCESS_DENIED on a desktop switch), the engine falls back
/// to GDI capture (CopyFromScreen, the pre-existing preview path's
/// mechanism) with tile-diff damage, and every frame header names
/// capture:"gdi" — the fallback is visible in the protocol, never
/// disguised as DXGI. If the encoder cannot start, stream_start
/// fails with the step + HRESULT and there is no stream.
///
/// Protected surfaces: Desktop Duplication is refused outright on
/// the secure desktop (ACCESS_DENIED) and windows marked
/// WDA_EXCLUDEFROMCAPTURE render black in both capture paths by
/// platform design — the engine adds no path around either, and the
/// stream_start/frame results report capture death by name.
/// </summary>
public sealed class StreamEngine : IDisposable
{
    private const int TargetFps = 30;
    private const int KeyframeKeepaliveMs = 5000;
    private const int RingCapacity = 90;

    private readonly object _gate = new();
    private readonly Queue<(StreamProtocol.FrameHeader Header, byte[] Body)> _ring = new();
    private CancellationTokenSource? _cts;
    private Thread? _pump;
    private H264Encoder? _encoder;
    private DxgiCapture? _dxgi;
    private DamageTracker _gdiDamage = new();
    private string _captureKind = "";
    private string _encoderName = "";
    private bool _encoderHardware;
    private int _width, _height, _monitor;
    private long _seq;
    private long _framesEncoded, _framesSkippedStatic, _bytesEncoded;
    private string? _fatal;

    public bool Running { get { lock (_gate) return _pump is not null; } }

    public (bool Ok, string Text) Start(int monitor)
    {
        lock (_gate)
        {
            if (_pump is not null) StopLocked();
            _fatal = null;
            var monitors = DxgiCapture.EnumerateMonitors();
            if (monitor < 0 || monitor >= monitors.Count)
                return (false, $"monitor {monitor} does not exist ({monitors.Count} monitor(s))");
            var m = monitors[monitor];
            _monitor = monitor;
            _width = m.W; _height = m.H;
            // Even dimensions for NV12/H.264.
            if ((_width & 1) != 0) _width--;
            if ((_height & 1) != 0) _height--;

            var dxgi = new DxgiCapture();
            bool dxgiStarted;
            string? dxgiStartError;
            try
            {
                dxgiStarted = dxgi.Start(monitor);
                dxgiStartError = dxgi.LastError;
            }
            catch (Exception ex)
            {
                // A DXGI failure must degrade to the GDI fallback,
                // never escape as an engine error: hybrid-GPU and
                // virtual-adapter machines can throw inside the COM
                // interop (e.g. an adapter refusing the IDXGIAdapter1
                // QueryInterface) before Start can return false.
                // Found live on the reference laptop, 2026-11-19 (Fix16
                // proof): InvalidCastException E_NOINTERFACE from
                // EnumAdapters1 killed the stream start with a 502.
                dxgiStarted = false;
                dxgiStartError = $"DXGI capture threw ({ex.GetType().Name}): {ex.Message}";
            }
            if (dxgiStarted)
            {
                _dxgi = dxgi;
                _captureKind = "dxgi";
                _width = dxgi.Width & ~1;
                _height = dxgi.Height & ~1;
            }
            else
            {
                var dxgiError = dxgiStartError;
                dxgi.Dispose();
                _dxgi = null;
                _captureKind = "gdi";
                _gdiDamage = new DamageTracker();
                if (dxgiError is not null && dxgiError.Contains("ACCESS_DENIED"))
                    return (false, $"capture refused by the platform: {dxgiError}");
            }
            var bitrate = Math.Clamp(_width * _height * 4, 1_500_000, 12_000_000);
            if (!H264Encoder.TryCreate(_width, _height, TargetFps, bitrate, out var encoder, out var encError))
            {
                _dxgi?.Dispose(); _dxgi = null;
                return (false, $"H.264 encoder start failed: {encError}");
            }
            _encoder = encoder;
            _encoderName = encoder!.Description;
            _encoderHardware = encoder.Hardware;
            _seq = 0; _framesEncoded = 0; _framesSkippedStatic = 0; _bytesEncoded = 0;
            _ring.Clear();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _pump = new Thread(() => Pump(token)) { IsBackground = true, Name = "acp-stream-pump" };
            _pump.Start();
            return (true, JsonSerializer.Serialize(new
            {
                streaming = true,
                monitor,
                width = _width,
                height = _height,
                capture = _captureKind,
                encoder = _encoderName,
                hardware = _encoderHardware,
                codec = "h264",
                fps = TargetFps,
            }));
        }
    }

    public (bool Ok, string Text) GetFrame(long afterSeq)
    {
        lock (_gate)
        {
            if (_fatal is not null) return (false, _fatal);
            // BD-WIN-AGENT F12: a viewer that fell more than the
            // ring holds behind has MISSED frames that no longer
            // exist. The pre-fix code silently served the oldest
            // surviving delta — undecodable without its keyframe,
            // with no gap signal. Now: say "gap" out loud and force
            // a keyframe so the viewer's next frame is decodable.
            if (_ring.Count > 0 && Acp.Shared.Streaming.RingGap.HasGap(afterSeq, _ring.Peek().Header.Seq, _seq))
            {
                _encoder?.RequestKeyFrame();
                return (true, JsonSerializer.Serialize(new
                {
                    seq = _seq,
                    gap = true,
                    oldestSeq = _ring.Peek().Header.Seq,
                    needKeyframe = true,
                }));
            }
            foreach (var (header, body) in _ring)
            {
                if (header.Seq > afterSeq)
                    return (true, JsonSerializer.Serialize(new
                    {
                        seq = header.Seq,
                        data = Convert.ToBase64String(body),
                    }));
            }
            return (true, JsonSerializer.Serialize(new { seq = _seq, empty = true }));
        }
    }

    public (bool Ok, string Text) Stop()
    {
        lock (_gate) StopLocked();
        return (true, "stream stopped");
    }

    public string StatsJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new
            {
                running = _pump is not null,
                capture = _captureKind,
                encoder = _encoderName,
                hardware = _encoderHardware,
                width = _width,
                height = _height,
                seq = _seq,
                framesEncoded = _framesEncoded,
                framesSkippedStatic = _framesSkippedStatic,
                bytesEncoded = _bytesEncoded,
                fatal = _fatal,
            });
    }

    public static string MonitorsJson()
    {
        var monitors = DxgiCapture.EnumerateMonitors().Select(m => new
        {
            index = m.Index, x = m.X, y = m.Y, width = m.W, height = m.H, primary = m.Primary,
        }).ToArray();
        return JsonSerializer.Serialize(monitors);
    }

    private void StopLocked()
    {
        try { _cts?.Cancel(); } catch { }
        try { _pump?.Join(1500); } catch { }
        _pump = null;
        _cts = null;
        _encoder?.Dispose(); _encoder = null;
        _dxgi?.Dispose(); _dxgi = null;
        _ring.Clear();
    }

    private void Pump(CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        long lastEncodeMs = -KeyframeKeepaliveMs;
        long lastKeyframeMs = -KeyframeKeepaliveMs;
        var frameDuration100ns = 10_000_000L / TargetFps;
        var originX = 0; var originY = 0;
        lock (_gate)
        {
            if (_dxgi is not null) { originX = _dxgi.OriginX; originY = _dxgi.OriginY; }
            else
            {
                var monitors = DxgiCapture.EnumerateMonitors();
                if (_monitor < monitors.Count) { originX = monitors[_monitor].X; originY = monitors[_monitor].Y; }
            }
        }
        while (!token.IsCancellationRequested)
        {
            try
            {
                byte[]? bgra = null;
                var stride = 0;
                StreamProtocol.DamageRect? damage = null;
                var presented = false;
                if (_dxgi is not null)
                {
                    var frame = _dxgi.NextFrame(12);
                    if (frame is null)
                    {
                        if (_dxgi.LastError is not null)
                        {
                            // Capture died by name (ACCESS_LOST /
                            // ACCESS_DENIED / disconnect): fall back
                            // to GDI unless the platform refused —
                            // a refusal is a protected-surface fact,
                            // not a cue to route around it.
                            if (_dxgi.LastError.Contains("ACCESS_DENIED"))
                            {
                                lock (_gate) _fatal = $"capture ended: {_dxgi.LastError}";
                                return;
                            }
                            lock (_gate)
                            {
                                _dxgi.Dispose(); _dxgi = null;
                                _captureKind = "gdi";
                                _gdiDamage = new DamageTracker();
                            }
                            continue;
                        }
                        // Timeout: nothing presented.
                    }
                    else
                    {
                        bgra = frame.Bgra; stride = frame.Stride; damage = frame.Damage;
                        presented = frame.Accumulated || frame.Damage is not null;
                        if (!presented && frame.Damage is null)
                        {
                            // Pointer-only presentation: no pixels
                            // changed; still refresh the cursor
                            // position on the keepalive cadence below.
                        }
                    }
                }
                else
                {
                    bgra = CaptureGdi(originX, originY, _width, _height, out stride);
                    if (bgra is not null)
                    {
                        damage = _gdiDamage.Diff(bgra, _width, _height, stride);
                        presented = damage is not null;
                    }
                    Thread.Sleep(10);
                }

                var nowMs = sw.ElapsedMilliseconds;
                var keepaliveDue = nowMs - lastKeyframeMs >= KeyframeKeepaliveMs;
                if (!presented && !keepaliveDue)
                {
                    lock (_gate) _framesSkippedStatic++;
                    continue;
                }
                if (bgra is null) continue; // keepalive due but DXGI gave no pixels this tick
                if (nowMs - lastEncodeMs < 1000 / TargetFps && presented && !keepaliveDue) continue;
                lastEncodeMs = nowMs;

                var wantKeyframe = keepaliveDue || _framesEncoded == 0;
                if (wantKeyframe) _encoder?.RequestKeyFrame();
                var nv12 = H264Decoder.BgraToNv12(bgra, _width, _height, stride);
                var captureMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var aus = _encoder?.Encode(nv12, nowMs * 10_000L, frameDuration100ns)
                          ?? Array.Empty<EncodedAu>();
                NativeMethods.GetCursorPos(out var cursor);
                foreach (var au in aus)
                {
                    if (au.Data.Length == 0) continue;
                    if (!Acp.Shared.Streaming.H264.IsValidAccessUnit(au.Data, au.Keyframe)) continue;
                    lock (_gate)
                    {
                        _seq++;
                        var header = new StreamProtocol.FrameHeader(
                            Seq: _seq,
                            PtsMs: nowMs,
                            CaptureMs: captureMs,
                            Keyframe: au.Keyframe,
                            Width: _width, Height: _height,
                            Monitor: _monitor,
                            Codec: "h264",
                            Encoder: _encoderName,
                            Hardware: _encoderHardware,
                            Capture: _captureKind,
                            Damage: au.Keyframe ? null : damage,
                            CursorX: cursor.X - originX,
                            CursorY: cursor.Y - originY);
                        var body = StreamProtocol.Pack(header, au.Data);
                        _ring.Enqueue((header, body));
                        while (_ring.Count > RingCapacity) _ring.Dequeue();
                        _framesEncoded++;
                        _bytesEncoded += au.Data.Length;
                        if (au.Keyframe) lastKeyframeMs = nowMs;
                    }
                }
                if (aus.Count == 0 && wantKeyframe)
                {
                    // The encoder buffered the forced keyframe; its
                    // AU emerges on a later input. Nudge with the
                    // same frame once (async MFTs commonly lag one).
                    var aus2 = _encoder?.Encode(nv12, (nowMs + 33) * 10_000L, frameDuration100ns)
                               ?? Array.Empty<EncodedAu>();
                    foreach (var au in aus2)
                    {
                        if (au.Data.Length == 0 || !Acp.Shared.Streaming.H264.IsValidAccessUnit(au.Data, au.Keyframe)) continue;
                        lock (_gate)
                        {
                            _seq++;
                            var header = new StreamProtocol.FrameHeader(
                                Seq: _seq, PtsMs: nowMs + 33, CaptureMs: captureMs,
                                Keyframe: au.Keyframe, Width: _width, Height: _height,
                                Monitor: _monitor, Codec: "h264", Encoder: _encoderName,
                                Hardware: _encoderHardware, Capture: _captureKind,
                                Damage: au.Keyframe ? null : damage,
                                CursorX: cursor.X - originX, CursorY: cursor.Y - originY);
                            var body = StreamProtocol.Pack(header, au.Data);
                            _ring.Enqueue((header, body));
                            while (_ring.Count > RingCapacity) _ring.Dequeue();
                            _framesEncoded++;
                            _bytesEncoded += au.Data.Length;
                            if (au.Keyframe) lastKeyframeMs = nowMs;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lock (_gate) _fatal = $"stream pump error ({ex.GetType().Name}): {ex.Message}";
                return;
            }
        }
    }

    private static byte[]? CaptureGdi(int x, int y, int width, int height, out int stride)
    {
        stride = width * 4;
        try
        {
            using var bmp = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
                g.CopyFromScreen(x, y, 0, 0, new Size(width, height), CopyPixelOperation.SourceCopy);
            var data = bmp.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            try
            {
                var bytes = new byte[stride * height];
                for (var row = 0; row < height; row++)
                    System.Runtime.InteropServices.Marshal.Copy(data.Scan0 + row * data.Stride, bytes, row * stride, stride);
                return bytes;
            }
            finally { bmp.UnlockBits(data); }
        }
        catch { return null; }
    }

    public void Dispose() { lock (_gate) StopLocked(); }
}
