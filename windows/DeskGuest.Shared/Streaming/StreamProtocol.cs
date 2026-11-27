using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Streaming;

/// <summary>
/// DeskGuest session-stream wire format v1 (Block D, mesh contract v2 —
/// additive over MESH-CONTRACT v1). One H.264 access unit (AU) per
/// envelope, carried as the body of GET /mesh/stream/frame:
///
///   [0..4)   magic "DGSF"
///   [4..6)   u16 LE format version (= 1)
///   [6..8)   u16 LE header length H (JSON, UTF-8, ≤ 4096)
///   [8..8+H) header JSON: {seq, ptsMs, captureMs, keyframe, width,
///            height, monitor, codec:"h264", encoder, hardware,
///            capture:"dxgi"|"gdi", damage:{x,y,w,h}|null(full)}
///   [8+H..)  the access unit in Annex B byte-stream format
///            (start-code delimited NAL units)
///
/// The parser is a SECURITY boundary: viewer decoders consume what
/// it accepts, so it is fail-closed and allocation-bounded — bad
/// magic, oversized headers/AUs, truncated bodies, non-Annex-B
/// payloads, and keyframes without SPS/PPS/IDR are all refused
/// before a single byte reaches a codec. The fuzz battery in
/// StreamDestructionTests is its regression suite.
/// </summary>
public static class StreamProtocol
{
    public const ushort Version = 1;
    public const int MaxHeaderBytes = 4096;
    public const int MaxAccessUnitBytes = 8 * 1024 * 1024;
    public const int FixedHeaderBytes = 8;

    public sealed record FrameHeader(
        long Seq,
        long PtsMs,
        long CaptureMs,
        bool Keyframe,
        int Width,
        int Height,
        int Monitor,
        string Codec,
        string Encoder,
        bool Hardware,
        string Capture,
        DamageRect? Damage,
        int CursorX = -1,
        int CursorY = -1);

    public sealed record DamageRect(int X, int Y, int W, int H);

    public sealed record Frame(FrameHeader Header, byte[] AccessUnit);

    public static byte[] Pack(FrameHeader header, ReadOnlySpan<byte> accessUnit)
    {
        if (accessUnit.Length == 0 || accessUnit.Length > MaxAccessUnitBytes)
            throw new ArgumentOutOfRangeException(nameof(accessUnit));
        var headerJson = JsonSerializer.Serialize(new
        {
            seq = header.Seq, ptsMs = header.PtsMs, captureMs = header.CaptureMs,
            keyframe = header.Keyframe, width = header.Width, height = header.Height,
            monitor = header.Monitor, codec = header.Codec, encoder = header.Encoder,
            hardware = header.Hardware, capture = header.Capture,
            cursorX = header.CursorX, cursorY = header.CursorY,
            damage = header.Damage is null ? null : new { x = header.Damage.X, y = header.Damage.Y, w = header.Damage.W, h = header.Damage.H },
        });
        var headerBytes = Encoding.UTF8.GetBytes(headerJson);
        if (headerBytes.Length > MaxHeaderBytes)
            throw new ArgumentOutOfRangeException(nameof(header));
        var body = new byte[FixedHeaderBytes + headerBytes.Length + accessUnit.Length];
        body[0] = (byte)'D'; body[1] = (byte)'G'; body[2] = (byte)'S'; body[3] = (byte)'F';
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(6), (ushort)headerBytes.Length);
        headerBytes.CopyTo(body.AsSpan(FixedHeaderBytes));
        accessUnit.CopyTo(body.AsSpan(FixedHeaderBytes + headerBytes.Length));
        return body;
    }

    /// <summary>Parse one envelope. Null on ANY defect — callers
    /// treat null as "drop the frame", never as "try to decode".</summary>
    public static Frame? TryParse(ReadOnlySpan<byte> body)
    {
        if (body.Length < FixedHeaderBytes + 2) return null;
        if (body[0] != (byte)'D' || body[1] != (byte)'G' || body[2] != (byte)'S' || body[3] != (byte)'F') return null;
        if (BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(4)) != Version) return null;
        var headerLen = BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(6));
        if (headerLen == 0 || headerLen > MaxHeaderBytes) return null;
        if (body.Length < FixedHeaderBytes + headerLen + 1) return null;
        var au = body.Slice(FixedHeaderBytes + headerLen);
        if (au.Length > MaxAccessUnitBytes) return null;
        FrameHeader? header;
        try
        {
            using var doc = JsonDocument.Parse(body.Slice(FixedHeaderBytes, headerLen).ToArray());
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object) return null;
            header = new FrameHeader(
                Seq: Long(r, "seq"), PtsMs: Long(r, "ptsMs"), CaptureMs: Long(r, "captureMs"),
                Keyframe: r.TryGetProperty("keyframe", out var kf) && kf.ValueKind == JsonValueKind.True,
                Width: Int(r, "width"), Height: Int(r, "height"), Monitor: Int(r, "monitor"),
                Codec: Str(r, "codec"), Encoder: Str(r, "encoder"),
                Hardware: r.TryGetProperty("hardware", out var hw) && hw.ValueKind == JsonValueKind.True,
                Capture: Str(r, "capture"),
                Damage: ParseDamage(r),
                CursorX: IntOr(r, "cursorX", -1),
                CursorY: IntOr(r, "cursorY", -1));
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException)
        {
            // Fail-closed means NEVER throwing: JsonDocument parses
            // lazily, so a header string carrying invalid UTF-8 only
            // fails when GetString() transcodes it — that surfaces as
            // InvalidOperationException, not JsonException (found by
            // the mutation fuzz battery, Block D recovery 2026-11-19).
            return null;
        }
        if (header is null) return null;
        if (ReferenceEquals(header.Damage, OutOfFrameSentinel)) return null; // F12: damage rect outside the frame
        if (header.Codec != "h264") return null;
        if (header.Width <= 0 || header.Width > 16384 || header.Height <= 0 || header.Height > 16384) return null;
        if (header.Seq < 0) return null;
        var auCopy = au.ToArray();
        if (!H264.IsValidAccessUnit(auCopy, header.Keyframe)) return null;
        return new Frame(header, auCopy);
    }

    private static DamageRect? ParseDamage(JsonElement root)
    {
        if (!root.TryGetProperty("damage", out var d) || d.ValueKind != JsonValueKind.Object) return null;
        var rect = new DamageRect(Int(d, "x"), Int(d, "y"), Int(d, "w"), Int(d, "h"));
        if (rect.W <= 0 || rect.H <= 0) return null;
        // BD-SHARED-SESSION F12: a damage rect must be CONTAINED in
        // the frame it describes. ParseDamage runs before the
        // caller's width/height validation, so containment is
        // checked here against the header's own dimensions; an
        // out-of-frame rect is a lying envelope — refuse it (null
        // damage would silently widen to full-frame, so the whole
        // parse fails closed instead: see TryParse's damage check).
        var w = Int(root, "width"); var h = Int(root, "height");
        if (w <= 0 || h <= 0) return rect; // dimensions themselves are refused by TryParse
        return rect.X >= 0 && rect.Y >= 0 && rect.X + rect.W <= w && rect.Y + rect.H <= h
            ? rect : OutOfFrameSentinel;
    }

    /// <summary>Marker for a present-but-invalid damage rect, so
    /// TryParse can refuse the frame instead of treating the rect
    /// as absent (full-frame).</summary>
    internal static readonly DamageRect OutOfFrameSentinel = new(-1, -1, -1, -1);

    private static long Long(JsonElement r, string n) =>
        r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var x) ? x : -1;
    private static int Int(JsonElement r, string n) =>
        r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var x) ? x : 0;
    private static int IntOr(JsonElement r, string n, int fallback) =>
        r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var x) ? x : fallback;
    private static string Str(JsonElement r, string n) =>
        r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}

/// <summary>Minimal Annex B H.264 validation — enough to keep
/// malformed bytes away from hardware decoders: every NAL must be
/// start-code delimited with a sane header, the AU must contain at
/// least one VCL or IDR unit, and a keyframe AU must carry SPS (7),
/// PPS (8) and IDR (5). Deliberately NOT a full parser: the codec
/// remains the authority on decoding; this layer is the bouncer.</summary>
public static class H264
{
    /// <summary>NAL unit types in order of appearance.</summary>
    public static IReadOnlyList<int> NalTypes(ReadOnlySpan<byte> au)
    {
        var types = new List<int>();
        var i = 0;
        while (i + 3 < au.Length)
        {
            var sc = StartCodeLength(au, i);
            if (sc == 0) { i++; continue; }
            var nalStart = i + sc;
            if (nalStart >= au.Length) break;
            var header = au[nalStart];
            if ((header & 0x80) != 0) return Array.Empty<int>(); // forbidden_zero_bit set — corrupt
            types.Add(header & 0x1F);
            i = nalStart + 1;
            // Skip to next start code (payload scan; emulation
            // prevention makes false positives vanishingly rare and
            // a miss only mis-splits, never invents a NAL).
            while (i + 3 < au.Length && StartCodeLength(au, i) == 0) i++;
        }
        return types;
    }

    public static bool IsValidAccessUnit(ReadOnlySpan<byte> au, bool expectKeyframe)
    {
        if (au.Length < 5) return false;
        if (StartCodeLength(au, 0) == 0) return false; // must START with a start code
        var types = NalTypes(au);
        if (types.Count == 0) return false;
        if (types.Any(t => t is 0 or > 12)) return false; // reserved/unspecified in High profile AU context
        var hasSlice = types.Any(t => t is 1 or 5);
        if (!hasSlice) return false;
        // The keyframe flag is a claim about the NALs; the NALs are
        // the truth. An IDR-bearing AU claimed as a delta (or a
        // delta claimed as a keyframe) is a lying envelope — reject
        // it in both directions (the Android parser port enforces
        // the identical rule).
        if (types.Contains(5) != expectKeyframe) return false;
        if (expectKeyframe)
        {
            if (!types.Contains(7) || !types.Contains(8) || !types.Contains(5)) return false;
            // SPS must precede the IDR it describes.
            // (Block C transport lane, 2026-11-19: minimal compile
            // unblock — IReadOnlyList<int> has no IndexOf; semantics
            // unchanged, first-occurrence indices compared as before.)
            var idxSps = -1; var idxIdr = -1;
            for (var i = 0; i < types.Count; i++)
            {
                if (types[i] == 7 && idxSps < 0) idxSps = i;
                if (types[i] == 5 && idxIdr < 0) idxIdr = i;
            }
            if (idxSps > idxIdr) return false;
        }
        return true;
    }

    private static int StartCodeLength(ReadOnlySpan<byte> b, int i)
    {
        if (i + 3 < b.Length && b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) return 3;
        if (i + 4 < b.Length && b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 0 && b[i + 3] == 1) return 4;
        return 0;
    }
}

/// <summary>
/// Damage tracking over raw BGRA frames (tile grid hashing). The
/// stream pipeline consults it BEFORE encoding: a frame whose tiles
/// all match the previous frame is not encoded at all (the encoder
/// emits nothing for a static screen beyond the keyframe cadence,
/// which the caller enforces with a clock). A changed frame yields
/// the union of dirty tiles as the damage rect carried in the frame
/// header — viewers may use it for partial redraw, and the stats
/// prove the pipeline is damage-aware rather than full-frame.
/// </summary>
public sealed class DamageTracker
{
    public const int TileSize = 64;
    private ulong[]? _tiles;
    private int _tilesX, _tilesY, _width, _height;

    /// <summary>Returns null when the frame is identical to the
    /// previous one; otherwise the damage rect (full frame on the
    /// first frame or a size change).</summary>
    public StreamProtocol.DamageRect? Diff(ReadOnlySpan<byte> bgra, int width, int height, int stride)
    {
        if (width <= 0 || height <= 0 || stride < width * 4) return new StreamProtocol.DamageRect(0, 0, width, height);
        // BD-SHARED-SESSION F12: a short buffer fails CLOSED (full
        // damage) instead of throwing out of Slice() mid-hash.
        if (bgra.Length < (long)stride * height) return new StreamProtocol.DamageRect(0, 0, width, height);
        var tilesX = (width + TileSize - 1) / TileSize;
        var tilesY = (height + TileSize - 1) / TileSize;
        if (_tiles is null || tilesX != _tilesX || tilesY != _tilesY || width != _width || height != _height)
        {
            _tilesX = tilesX; _tilesY = tilesY; _width = width; _height = height;
            _tiles = ComputeTiles(bgra, width, height, stride, tilesX, tilesY);
            return new StreamProtocol.DamageRect(0, 0, width, height);
        }
        var next = ComputeTiles(bgra, width, height, stride, tilesX, tilesY);
        int minTx = tilesX, minTy = tilesY, maxTx = -1, maxTy = -1;
        for (var ty = 0; ty < tilesY; ty++)
            for (var tx = 0; tx < tilesX; tx++)
                if (next[ty * tilesX + tx] != _tiles[ty * tilesX + tx])
                {
                    if (tx < minTx) minTx = tx;
                    if (ty < minTy) minTy = ty;
                    if (tx > maxTx) maxTx = tx;
                    if (ty > maxTy) maxTy = ty;
                }
        _tiles = next;
        if (maxTx < 0) return null; // static — nothing to encode
        var x = minTx * TileSize;
        var y = minTy * TileSize;
        var w = Math.Min(width, (maxTx + 1) * TileSize) - x;
        var h = Math.Min(height, (maxTy + 1) * TileSize) - y;
        return new StreamProtocol.DamageRect(x, y, w, h);
    }

    public void Reset() { _tiles = null; }

    private static ulong[] ComputeTiles(ReadOnlySpan<byte> bgra, int width, int height, int stride, int tilesX, int tilesY)
    {
        var tiles = new ulong[tilesX * tilesY];
        for (var ty = 0; ty < tilesY; ty++)
        {
            var y0 = ty * TileSize;
            var y1 = Math.Min(height, y0 + TileSize);
            for (var tx = 0; tx < tilesX; tx++)
            {
                var x0 = tx * TileSize;
                var x1 = Math.Min(width, x0 + TileSize);
                // FNV-1a over EVERY pixel of the tile
                // (BD-SHARED-SESSION F12: the previous strided
                // sample — every 2nd pixel, under a comment claiming
                // every 4th — skipped 1-px changes on odd rows/cols
                // entirely, so a caret or thin line read as static
                // until the next keyframe. Correctness of the
                // static verdict outranks the saved CPU here.)
                ulong hash = 1469598103934665603UL;
                for (var y = y0; y < y1; y++)
                {
                    var row = bgra.Slice(y * stride);
                    for (var x = x0; x < x1; x++)
                    {
                        var p = x * 4;
                        hash = (hash ^ row[p]) * 1099511628211UL;
                        hash = (hash ^ row[p + 1]) * 1099511628211UL;
                        hash = (hash ^ row[p + 2]) * 1099511628211UL;
                    }
                }
                tiles[ty * tilesX + tx] = hash;
            }
        }
        return tiles;
    }
}
