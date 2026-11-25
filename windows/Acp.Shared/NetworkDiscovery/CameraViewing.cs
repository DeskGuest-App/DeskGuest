using System.Net;
using System.Xml;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Roster;

namespace Acp.Shared.NetworkDiscovery;

// =====================================================================
// RMM-11 EXTENSION — Camera viewing (ADOPTED 2026-11-20 15:30 CT). The bounds below are the adoption itself, not commentary:
//
//  * OPEN PROTOCOLS ONLY. ONVIF/RTSP cameras are viewable.
//    Cloud-locked consumer cameras (Ring/Nest/Wyze class) are
//    identified at discovery and filed INVENTORY-ONLY with the
//    reason stated plainly — never a view that pretends to work.
//  * VIEWING IS NOT RECORDING. Live view + snapshots only. There
//    is NO record/retain/motion/NVR surface in this file at all —
//    the absence is the feature. Camera audio is OFF by default:
//    a view carries no audio unless a separate explicit policy
//    (rmm.camera_viewing.audio.enabled) AND a stronger grant
//    (admin right on the camera's device group) both say so.
//  * RIGHTS + AUDIT. "View" is a D12 grant right (user-group ×
//    device-group × view) checked against the roster. EVERY view
//    — started, ended, and every REFUSED attempt — is a
//    hash-chained audit event (who, which camera, when, duration
//    at close). No presence fiction: a camera has no person at it
//    to consent; control is permissions + audit, nothing else.
//  * POLICY. rmm.camera_viewing.enabled is seeded OFF in the
//    RMM-07 registry: a view refuses unless policy enables it AND
//    the grant exists AND the camera's ViewCapability is
//    onvif/rtsp. All three, every time, re-read per view.
//  * Viewing RIDES the existing stream machinery: this layer
//    validates and hands an RTSP URI to the stream layer through
//    ICameraStreamSink — it builds no video stack of its own.
// =====================================================================

public static class CameraPolicyKeys
{
    public const string ViewingEnabled = "rmm.camera_viewing.enabled";
    public const string AudioEnabled = "rmm.camera_viewing.audio.enabled";
}

/// <summary>The D12 right this extension adds: "view". It joins
/// RosterService.ValidRights ({ use, enroll, admin, view }) so
/// grants are created, stored and checked by the roster's own
/// machinery — there is no shadow permission store.</summary>
public static class CameraRights
{
    public const string View = "view";
    /// <summary>D38-F12(c): the admin right by constant, not a
    /// literal at the call site.</summary>
    public const string Admin = "admin";
}

// ---- ONVIF model (parsers over fixtures; no network in this layer) -----------

public sealed record OnvifDeviceInfo(
    string? XAddr, IReadOnlyList<string> Types, IReadOnlyList<string> Scopes,
    string? Make, string? Model)
{
    public IReadOnlyList<string> Types { get; init; } = Types ?? Array.Empty<string>();
    public IReadOnlyList<string> Scopes { get; init; } = Scopes ?? Array.Empty<string>();
}

public sealed record OnvifProfile(string Token, string Name);

/// <summary>ONVIF wire parsers: WS-Discovery ProbeMatches and the
/// GetProfiles / GetStreamUri responses, as PURE functions over
/// byte fixtures. XML is parsed with DTDs PROHIBITED and a hard
/// size cap — a hostile camera (or a hostile "camera") answering
/// discovery gets its XML refused, never parsed into an XXE or a
/// billion-laughs. Malformed input is null, never an exception.</summary>
public static class OnvifParsers
{
    public const int MaxXmlBytes = 256 * 1024;

    private static XmlDocument? LoadBounded(ReadOnlySpan<byte> xml)
    {
        if (xml.Length == 0 || xml.Length > MaxXmlBytes) return null;
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxXmlBytes,
                IgnoreWhitespace = true,
            };
            using var ms = new MemoryStream(xml.ToArray());
            using var reader = XmlReader.Create(ms, settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            return doc;
        }
        catch { return null; }
    }

    private static IEnumerable<XmlElement> Descendants(XmlNode node, string localName)
    {
        foreach (XmlNode child in node.ChildNodes)
        {
            if (child is XmlElement el)
            {
                if (el.LocalName == localName) yield return el;
                foreach (var d in Descendants(el, localName)) yield return d;
            }
        }
    }

    /// <summary>Parse a WS-Discovery ProbeMatches document. Make /
    /// model come from the ONVIF scopes the device itself declares
    /// (onvif://www.onvif.org/manufacturer/… , …/name/…); undeclared
    /// facts stay null — never guessed from the address.</summary>
    public static OnvifDeviceInfo? ParseProbeMatches(ReadOnlySpan<byte> xml)
    {
        var doc = LoadBounded(xml);
        if (doc is null) return null;
        var match = Descendants(doc, "ProbeMatch").FirstOrDefault();
        if (match is null) return null;
        var xaddr = Descendants(match, "XAddrs").FirstOrDefault()?.InnerText.Trim().Split(' ')
            .FirstOrDefault(s => s.Length > 0);
        var types = (Descendants(match, "Types").FirstOrDefault()?.InnerText ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var scopes = (Descendants(match, "Scopes").FirstOrDefault()?.InnerText ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        string? FromScope(string marker) => scopes.FirstOrDefault(s =>
            s.Contains(marker, StringComparison.OrdinalIgnoreCase)) is { } hit
            ? Uri.UnescapeDataString(hit[(hit.IndexOf(marker, StringComparison.OrdinalIgnoreCase) + marker.Length)..])
            : null;
        return new OnvifDeviceInfo(xaddr, types, scopes,
            FromScope("/manufacturer/") ?? FromScope("/mfr/"),
            FromScope("/name/") ?? FromScope("/model/"));
    }

    public static IReadOnlyList<OnvifProfile> ParseProfiles(ReadOnlySpan<byte> xml)
    {
        var doc = LoadBounded(xml);
        if (doc is null) return Array.Empty<OnvifProfile>();
        var profiles = new List<OnvifProfile>();
        foreach (var p in Descendants(doc, "Profiles"))
        {
            var token = p.GetAttribute("token");
            if (string.IsNullOrWhiteSpace(token)) continue;
            var name = Descendants(p, "Name").FirstOrDefault()?.InnerText.Trim() ?? token;
            profiles.Add(new OnvifProfile(token, name));
            if (profiles.Count >= 64) break;
        }
        return profiles;
    }

    /// <summary>The RTSP URI from a GetStreamUri response. Returned
    /// RAW: validation is RtspUriGuard's job, applied by the view
    /// service at registration AND again at view time — a URI is
    /// never trusted because a parser produced it.</summary>
    public static string? ParseStreamUri(ReadOnlySpan<byte> xml)
    {
        var doc = LoadBounded(xml);
        if (doc is null) return null;
        var uri = Descendants(doc, "Uri").FirstOrDefault()?.InnerText.Trim();
        return string.IsNullOrWhiteSpace(uri) ? null : uri;
    }
}

/// <summary>Cloud-locked consumer-camera identification. When
/// discovery fingerprints one of these brands AND the device shows
/// no local ONVIF/RTSP capability, the record is inventory-only —
/// with this reason, stated plainly. A device of the same brand
/// that DOES expose ONVIF/RTSP (e.g. RTSP-firmware Wyze) is
/// viewable: capability evidence outranks brand.</summary>
public static class CloudCameraClassifier
{
    // Longest first: "google nest" must win over "nest".
    private static readonly string[] CloudBrands =
        { "google nest", "ring", "nest", "wyze", "blink", "arlo" };

    /// <summary>Token-boundary brand match (D38-F6 fix): a brand
    /// matches only as a whole word (or whole multi-word phrase)
    /// in the make/model/sysDescr tokens — never as a substring
    /// inside another word ("ring" in Monitoring/String,
    /// "nest" in honest, "arlo" in Carlo must NOT label a camera
    /// cloud-locked; a false reason filed on a record is a defect).</summary>
    private static string? MatchBrand(string? make, string? model, string? sysDescr)
    {
        var tokens = $"{make} {model} {sysDescr}".ToLowerInvariant()
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim('.', ',', ';', ':', '(', ')', '[', ']', '"', '\''))
            .Where(t => t.Length > 0).ToList();
        foreach (var brand in CloudBrands)
        {
            var brandTokens = brand.Split(' ');
            for (var i = 0; i + brandTokens.Length <= tokens.Count; i++)
                if (brandTokens.SequenceEqual(tokens.Skip(i).Take(brandTokens.Length)))
                    return brand;
        }
        return null;
    }

    public static (bool CloudLocked, string? Reason) Classify(
        string? make, string? model, string? sysDescr, bool onvifCapable, bool rtspCapable)
    {
        if (onvifCapable || rtspCapable) return (false, null);
        var brand = MatchBrand(make, model, sysDescr);
        if (brand is null) return (false, null);
        return (true,
            $"Cloud-locked consumer camera ({brand}): this class of camera exposes no local ONVIF/RTSP stream — " +
            "it can be inventoried but not viewed locally. Inventory-only by the manufacturer's design, not an ACP failure.");
    }

    /// <summary>The ViewCapability + reason a discovery landing
    /// files for a camera, from capability evidence alone. This
    /// overload is the PROBED form: the caller ran a capability
    /// probe (ports + ONVIF presence) and the camera answered
    /// with no ONVIF/RTSP evidence.</summary>
    public static (string Capability, string? Reason) CapabilityFor(
        bool onvifCapable, bool rtspCapable, string? make, string? model, string? sysDescr) =>
        CapabilityFor(onvifCapable, rtspCapable, make, model, sysDescr, capabilityProbed: true);

    /// <summary>D38-F7 fix: "did not advertise" is only filed when
    /// a probe actually asked. A camera that was never probed gets
    /// the honest not-probed reason — the record never states an
    /// observation nobody made.</summary>
    public static (string Capability, string? Reason) CapabilityFor(
        bool onvifCapable, bool rtspCapable, string? make, string? model, string? sysDescr,
        bool capabilityProbed)
    {
        if (onvifCapable) return (CameraViewCapabilities.Onvif, null);
        if (rtspCapable) return (CameraViewCapabilities.Rtsp, null);
        var (locked, reason) = Classify(make, model, sysDescr, false, false);
        if (locked) return (CameraViewCapabilities.InventoryOnly, reason);
        return (CameraViewCapabilities.InventoryOnly, capabilityProbed
            ? "Camera was probed during discovery and did not advertise ONVIF or RTSP — inventory-only until it is profiled with an open protocol."
            : "Camera has not yet been probed for ONVIF/RTSP capability — inventory-only until discovery probes it; no capability claim is made.");
    }
}

// ---- RTSP URI guard (the SSRF line) -------------------------------------------

/// <summary>Validates an RTSP stream URI against the camera record
/// it claims to belong to. THE SSRF GUARD for the viewer: the URI's
/// host must be EXACTLY the registered camera IP (itself refused
/// at RMM-04 registration when loopback/link-local/multicast — and
/// re-checked here independently), the scheme is rtsp only, no
/// userinfo (credentials never ride a stored URI), no query, no
/// fragment, no traversal, and the port must be a plausible RTSP
/// port — a "camera" whose URI points at an internal service
/// (SSH/HTTP/the hub itself) is refused by name.</summary>
public static class RtspUriGuard
{
    public static readonly IReadOnlySet<int> AllowedPorts = new HashSet<int> { 554, 8554, 10554 };

    public static (bool Ok, string Reason, string? Normalized) Validate(UnmanagedAsset camera, string? rawUri)
    {
        if (camera is null || camera.Kind != UnmanagedAssetKinds.Camera)
            return (false, "stream URI target is not a camera record — refused", null);
        if (string.IsNullOrWhiteSpace(rawUri))
            return (false, "no stream URI — refused", null);
        var raw = rawUri.Trim();
        if (raw.Length > 1024 || raw.Any(char.IsControl))
            return (false, "stream URI is oversized or carries control characters — refused", null);
        // Traversal is checked on the RAW string: System.Uri
        // normalizes ".." segments away during parsing, so a guard
        // that only inspects the parsed path would wave a crafted
        // URI through on the strength of the parser's cleanup
        // (found by RmmCameraTests.RtspGuard — DG-RCAM-06 break).
        if (raw.Contains("..") || raw.Contains('\\'))
            return (false, "stream URI carries traversal sequences — refused", null);
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
            return (false, "stream URI does not parse — refused", null);
        if (!string.Equals(uri.Scheme, "rtsp", StringComparison.OrdinalIgnoreCase))
            return (false, $"stream URI scheme '{uri.Scheme}' is not rtsp — refused (ONVIF/RTSP only)", null);
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return (false, "stream URI carries userinfo — refused (credentials never ride a stored URI)", null);
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            return (false, "stream URI carries a query/fragment — refused", null);
        if (!IPAddress.TryParse(uri.Host, out var hostIp))
            return (false, "stream URI host is not an IP literal — refused (a hostname could resolve anywhere)", null);
        if (!NetworkAddressing.IsProbeableHost(hostIp))
            return (false, "stream URI host is loopback/link-local/multicast — refused (SSRF line)", null);
        if (camera.IpAddress is null || !IPAddress.TryParse(camera.IpAddress, out var cameraIp) ||
            !hostIp.Equals(cameraIp))
            return (false, "stream URI host is not the camera's registered address — refused (SSRF line: the viewer connects only to the camera itself)", null);
        var port = uri.Port;
        if (!AllowedPorts.Contains(port))
            return (false, $"stream URI port {port} is not an RTSP port — refused (SSRF line)", null);
        var path = uri.AbsolutePath ?? "/";
        if (path.Contains("..") || path.Contains('\\') || path.Contains("//"))
            return (false, "stream URI path carries traversal — refused", null);
        // D38-F10(a) fix: an IPv6 literal must be bracketed in a
        // URI, or the rebuilt URI is ambiguous/unparseable.
        var hostPart = hostIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{hostIp}]" : hostIp.ToString();
        return (true, "ok", $"rtsp://{hostPart}:{port}{path}");
    }
}

/// <summary>Snapshot path guard: a snapshot filename is BUILT from
/// the asset id + timestamp by the service (never caller-supplied),
/// and the resolved full path must stay under the snapshot base
/// directory. Any caller-shaped path segment is refused.</summary>
public static class SnapshotPathGuard
{
    /// <summary>D38-F12(b) fix: the timestamp is formatted with
    /// the INVARIANT culture (a th-TH clock must not file Buddhist-
    /// calendar years) and the filename carries milliseconds plus
    /// a service sequence number, so two snapshots in the same
    /// second never share a filename and overwrite each other.
    /// D38-F1 defence-in-depth: a UNC base is refused outright —
    /// a snapshot write to a network share leaks NTLM credentials
    /// and copies frames off the hub.</summary>
    public static string? Resolve(string baseDir, string assetId, DateTimeOffset now, long sequence = 0)
    {
        if (string.IsNullOrWhiteSpace(baseDir)) return null;
        if (baseDir.TrimStart().StartsWith(@"\\", StringComparison.Ordinal)) return null; // UNC
        var id = (assetId ?? "").Trim().ToLowerInvariant();
        if (id.Length == 0 || id.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_'))) return null;
        var fileName = FormattableString.Invariant($"{id}-{now:yyyyMMdd-HHmmss-fff}-{sequence}.jpg");
        string fullBase, full;
        try
        {
            fullBase = Path.GetFullPath(baseDir);
            full = Path.GetFullPath(Path.Combine(fullBase, fileName));
        }
        catch { return null; }
        var prefix = fullBase.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? full : null;
    }
}

// ---- the stream sink (rides the existing stream layer) -------------------------

/// <summary>The hand-off to ACP's existing stream/viewer machinery
/// (Block D StreamService + StreamProtocol): the camera layer
/// validates and presents an RTSP source; the stream layer carries
/// it. The production sink bridges to that service; tests use the
/// recorder. No second video stack exists.</summary>
public interface ICameraStreamSink
{
    (bool Ok, string Detail) OpenStream(string viewSessionId, string assetId, string rtspUri, bool audioEnabled);
    void CloseStream(string viewSessionId);
    (bool Ok, string Detail) CaptureSnapshot(string viewSessionId, string targetPath);
}

/// <summary>Recording test double for ICameraStreamSink.</summary>
public sealed class RecordingCameraStreamSink : ICameraStreamSink
{
    public List<(string SessionId, string AssetId, string Uri, bool Audio)> Opened { get; } = new();
    public List<string> Closed { get; } = new();
    public List<(string SessionId, string Path)> Snapshots { get; } = new();
    public bool FailOpen { get; set; }

    public (bool Ok, string Detail) OpenStream(string viewSessionId, string assetId, string rtspUri, bool audioEnabled)
    {
        if (FailOpen) return (false, "stream layer refused (recording double)");
        Opened.Add((viewSessionId, assetId, rtspUri, audioEnabled));
        return (true, "stream opened (recording double)");
    }

    public void CloseStream(string viewSessionId) => Closed.Add(viewSessionId);

    public (bool Ok, string Detail) CaptureSnapshot(string viewSessionId, string targetPath)
    {
        Snapshots.Add((viewSessionId, targetPath));
        return (true, "snapshot captured (recording double)");
    }
}

// ---- the view service -----------------------------------------------------------

public sealed record CameraViewSession(
    string SessionId, string ScopeId, string AssetId, string DeviceGroupId,
    string ActorUserId, DateTimeOffset StartedUtc, DateTimeOffset? EndedUtc, bool AudioEnabled)
{
    public bool IsActive => EndedUtc is null;
    public TimeSpan? Duration => EndedUtc is { } end ? end - StartedUtc : null;
}

public sealed record ViewStartResult(bool Ok, CameraViewSession? Session, string Reason);

/// <summary>The camera view service. Gates, in order, EVERY view:
/// camera record (kind + capability) → device-group assignment →
/// policy toggle → D12 view grant → RTSP URI re-validation →
/// audio gate. Every outcome — start, end, snapshot, and every
/// refusal — is appended to the shared hash-chained audit BEFORE
/// the caller learns it, so there is no audit-less path: a view
/// that cannot be audited does not start (the sink is only touched
/// after the start entry is chained).</summary>
public sealed class CameraViewService
{
    private readonly UnmanagedAssetRegister _register;
    private readonly RosterService _roster;
    private readonly ManagementPolicyEngine _policy;
    private readonly ChainedAuditLog _audit;
    private readonly ICameraStreamSink _sink;
    private readonly Func<DateTimeOffset> _now;

    private readonly Dictionary<string, string> _groupByAsset = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _uriByAsset = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CameraViewSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    // Lane A (camera ruling 2026-11-21 (a)): refused-STOP audit
    // aggregation. A refused STOP is always counted and
    // attributable, but a flood must not grow the hash chain
    // without limit: the FIRST refusal from an actor against a
    // session inside a rolling window is chained individually;
    // repeats inside the window are counted in memory and chained
    // as ONE aggregate entry when the window closes (on the first
    // refusal after expiry, or on FlushRefusedStopAggregates).
    // TotalRefusedStops always recovers the true total: individual
    // entries + aggregate counts + the still-open window's count.
    public static readonly TimeSpan RefusedStopWindow = TimeSpan.FromMinutes(5);
    private sealed class RefusedStopWindowState
    {
        public required string Actor;
        public required string SessionId;
        public required string AssetId;
        public DateTimeOffset WindowStartUtc;
        public int PendingCount;
    }
    private readonly Dictionary<string, RefusedStopWindowState> _refusedStopWindows = new(StringComparer.OrdinalIgnoreCase);
    private long _refusedStopsIndividual;
    private long _refusedStopsAggregated;

    /// <summary>Every refused STOP ever presented to this service:
    /// chained-individual + chained-aggregate + pending in-window.
    /// The total is always recoverable — aggregation hides nothing.</summary>
    public long TotalRefusedStops
    {
        get
        {
            lock (_gate)
                return _refusedStopsIndividual + _refusedStopsAggregated +
                       _refusedStopWindows.Values.Sum(w => (long)w.PendingCount);
        }
    }

    private void AuditRefusedStop(string actor, string sessionId, string assetId, string reason, DateTimeOffset now)
    {
        var key = (actor ?? "unknown") + "|" + (sessionId ?? "");
        RefusedStopWindowState? toFlush = null;
        var individual = false;
        lock (_gate)
        {
            if (_refusedStopWindows.TryGetValue(key, out var w) && now - w.WindowStartUtc < RefusedStopWindow)
            {
                w.PendingCount++;
            }
            else
            {
                if (w is not null && w.PendingCount > 0) toFlush = w;
                _refusedStopWindows[key] = new RefusedStopWindowState
                {
                    Actor = actor ?? "unknown", SessionId = sessionId ?? "", AssetId = assetId,
                    WindowStartUtc = now, PendingCount = 0,
                };
                _refusedStopsIndividual++;
                individual = true;
            }
        }
        if (toFlush is not null) AppendAggregate(toFlush);
        if (individual)
            _audit.Append("camera_view_stop_refused", AuditToken(actor),
                $"session={AuditToken(sessionId)} camera={AuditToken(assetId)} reason={reason}", now);
    }

    private void AppendAggregate(RefusedStopWindowState w)
    {
        lock (_gate) _refusedStopsAggregated += w.PendingCount;
        _audit.Append("camera_view_stop_refused_aggregate", AuditToken(w.Actor),
            $"session={AuditToken(w.SessionId)} camera={AuditToken(w.AssetId)} count={w.PendingCount} windowStart={w.WindowStartUtc:O} — repeated refused STOP attempts collapsed under the 2026-11-21 aggregation ruling; every attempt is counted here", _now());
    }

    /// <summary>Close every open aggregation window, chaining one
    /// aggregate entry per (actor, session) with pending repeats.
    /// Called by the hub duty cycle and at shutdown so no counted
    /// refusal ever lives only in memory longer than a window.</summary>
    public int FlushRefusedStopAggregates()
    {
        List<(string Actor, string SessionId, string AssetId, int Count, DateTimeOffset WindowStart)> pending;
        lock (_gate)
        {
            pending = _refusedStopWindows.Values.Where(w => w.PendingCount > 0)
                .Select(w => (w.Actor, w.SessionId, w.AssetId, w.PendingCount, w.WindowStartUtc)).ToList();
            foreach (var w in _refusedStopWindows.Values) w.PendingCount = 0;
            _refusedStopsAggregated += pending.Sum(x => (long)x.Count);
        }
        foreach (var x in pending)
            _audit.Append("camera_view_stop_refused_aggregate", AuditToken(x.Actor),
                $"session={AuditToken(x.SessionId)} camera={AuditToken(x.AssetId)} count={x.Count} windowStart={x.WindowStart:O} — repeated refused STOP attempts collapsed under the 2026-11-21 aggregation ruling; every attempt is counted here", _now());
        return pending.Count;
    }

    // ---- D38 fix state -------------------------------------------------
    // F1: the snapshot base directory is SERVICE-owned (hub
    // configuration at construction), never a per-call caller
    // parameter — a caller cannot aim snapshot writes at an
    // arbitrary folder or a UNC share.
    private readonly string _snapshotBaseDir;
    // F5: snapshots are rate-limited per session and retained
    // under a bounded policy — an open view must not become a
    // stored time-lapse (viewing is not recording).
    public static readonly TimeSpan MinSnapshotInterval = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan SnapshotRetention = TimeSpan.FromHours(24);
    public const int MaxTrackedSnapshots = 200;
    private readonly Dictionary<string, DateTimeOffset> _lastSnapshotBySession = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Path, DateTimeOffset CreatedUtc)> _snapshotFiles = new();
    private long _snapshotSequence;
    // F3: a view is not a one-time gate pass — sessions are
    // revalidated (grant, policy, group, lifecycle, audio) and
    // terminated when authorization evaporates, and no view may
    // outlive MaxViewDuration.
    public static readonly TimeSpan MaxViewDuration = TimeSpan.FromHours(8);
    // F12(a): ended sessions are pruned — kept for a bounded
    // window for duration reads, never forever.
    public static readonly TimeSpan EndedSessionRetention = TimeSpan.FromHours(1);
    public const int MaxEndedSessions = 100;
    // F8: snapshot refusals against unknown sessions aggregate
    // under the same counted-window discipline as refused stops,
    // so made-up session ids cannot grow the chain without limit.
    private readonly Dictionary<string, int> _snapshotRefusalWindows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _snapshotRefusalWindowStarts = new(StringComparer.OrdinalIgnoreCase);
    private long _refusedSnapshotsIndividual;
    private long _refusedSnapshotsAggregated;
    public long TotalRefusedSnapshots
    {
        get
        {
            lock (_gate)
                return _refusedSnapshotsIndividual + _refusedSnapshotsAggregated +
                       _snapshotRefusalWindows.Values.Sum(v => (long)v);
        }
    }

    /// <summary>D38-F8 fix: caller-supplied strings never enter an
    /// audit detail raw. Detail text is key=value shaped; a value
    /// carrying spaces or '=' could forge fields in a later parse,
    /// and unbounded strings make the chain a storage sink. Every
    /// interpolated caller value is flattened to a bounded,
    /// separator-free token.</summary>
    internal static string AuditToken(string? raw, int max = 64)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "no-actor-or-id";
        var chars = raw.Trim().Select(c =>
            char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or ':' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length <= max ? s : s[..max];
    }

    private void AuditRefusedSnapshotUnknownSession(string actor, string sessionId, DateTimeOffset now)
    {
        var key = AuditToken(actor) + "|" + AuditToken(sessionId);
        var individual = false;
        var flushCount = 0; DateTimeOffset flushStart = default;
        lock (_gate)
        {
            if (_snapshotRefusalWindows.TryGetValue(key, out var pending) &&
                now - _snapshotRefusalWindowStarts[key] < RefusedStopWindow)
            {
                _snapshotRefusalWindows[key] = pending + 1;
            }
            else
            {
                if (pending > 0) { flushCount = pending; flushStart = _snapshotRefusalWindowStarts[key]; _refusedSnapshotsAggregated += pending; }
                _snapshotRefusalWindows[key] = 0;
                _snapshotRefusalWindowStarts[key] = now;
                _refusedSnapshotsIndividual++;
                individual = true;
            }
        }
        if (flushCount > 0)
            _audit.Append("camera_snapshot_refused_aggregate", AuditToken(actor),
                $"session={AuditToken(sessionId)} count={flushCount} windowStart={flushStart:O} — repeated refused snapshot attempts collapsed; every attempt is counted here", now);
        if (individual)
            _audit.Append("camera_snapshot_refused", AuditToken(actor),
                $"session={AuditToken(sessionId)} reason=no active view", now);
    }

    public CameraViewService(
        UnmanagedAssetRegister register, RosterService roster,
        ManagementPolicyEngine policy, ChainedAuditLog audit,
        ICameraStreamSink sink, Func<DateTimeOffset>? now = null,
        string? snapshotBaseDir = null)
    {
        _register = register ?? throw new ArgumentNullException(nameof(register));
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        // F1: default snapshot home is under the app's own base
        // directory; the hub passes its data-dir path explicitly.
        _snapshotBaseDir = string.IsNullOrWhiteSpace(snapshotBaseDir)
            ? Path.Combine(AppContext.BaseDirectory, "camera-snapshots")
            : snapshotBaseDir;
    }

    /// <summary>The service-owned snapshot directory (F1).</summary>
    public string SnapshotBaseDir => _snapshotBaseDir;

    private void PruneEndedSessionsLocked(DateTimeOffset now)
    {
        var ended = _sessions.Values.Where(s => !s.IsActive)
            .OrderBy(s => s.EndedUtc).ToList();
        foreach (var s in ended)
        {
            var expired = now - s.EndedUtc!.Value > EndedSessionRetention;
            var overCap = _sessions.Values.Count(x => !x.IsActive) > MaxEndedSessions;
            if (!expired && !overCap) break;
            _sessions.Remove(s.SessionId);
            _lastSnapshotBySession.Remove(s.SessionId);
        }
    }

    public IReadOnlyList<CameraViewSession> Sessions
    {
        get
        {
            lock (_gate)
            {
                PruneEndedSessionsLocked(_now());
                return _sessions.Values.OrderBy(s => s.StartedUtc).ToList();
            }
        }
    }

    /// <summary>D38-F4 fix: gate-input authority. Group assignment
    /// decides whose 'view' grant applies and URI registration
    /// decides which LAN host the viewer connects to — both are
    /// structural acts. They now take an actor, require an admin
    /// right on the target device group or a company-admin seat
    /// (the roster's HasAdminRight; AI actors never pass, D9), and
    /// EVERY outcome — success and refusal — is hash-chained.</summary>
    private bool ActorMayAdministerCamera(UnmanagedAsset asset, string? actorUserId, string? deviceGroupId = null)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (_roster.IsCompanyAdmin(asset.ScopeId, actorUserId)) return true;
        var group = deviceGroupId;
        if (group is null) lock (_gate) _groupByAsset.TryGetValue(asset.AssetId, out group);
        return group is not null && _roster.HasAdminRight(asset.ScopeId, actorUserId, deviceGroupId: group);
    }

    /// <summary>File a camera into a device group (the viewable
    /// device class joins groups like any device). The group must
    /// exist in the camera's own scope — a cross-scope assignment
    /// is refused (D8 wall). Actor-gated + audited (F4).</summary>
    public bool AssignToDeviceGroup(string assetId, string deviceGroupId, string actorUserId)
    {
        var now = _now();
        var asset = _register.Get(assetId);
        if (asset is null || asset.Kind != UnmanagedAssetKinds.Camera)
        {
            _audit.Append("camera_group_assignment_refused", AuditToken(actorUserId),
                $"camera={AuditToken(assetId)} group={AuditToken(deviceGroupId)} reason=unknown camera", now);
            return false;
        }
        if (_roster.GetDeviceGroup(asset.ScopeId, deviceGroupId) is null)
        {
            _audit.Append("camera_group_assignment_refused", AuditToken(actorUserId),
                $"camera={AuditToken(asset.AssetId)} group={AuditToken(deviceGroupId)} reason=group not in camera scope", now);
            return false;
        }
        if (!ActorMayAdministerCamera(asset, actorUserId, deviceGroupId))
        {
            _audit.Append("camera_group_assignment_refused", AuditToken(actorUserId),
                $"camera={AuditToken(asset.AssetId)} group={AuditToken(deviceGroupId)} reason=actor holds no admin right on the target group", now);
            return false;
        }
        string? previous;
        lock (_gate)
        {
            _groupByAsset.TryGetValue(asset.AssetId, out previous);
            _groupByAsset[asset.AssetId] = deviceGroupId;
        }
        _audit.Append("camera_group_assigned", AuditToken(actorUserId),
            $"camera={AuditToken(asset.AssetId)} group={AuditToken(deviceGroupId)} previousGroup={AuditToken(previous)}", now);
        return true;
    }

    /// <summary>Register the camera's RTSP stream URI (from an
    /// ONVIF GetStreamUri response or an admin's entry). Validated
    /// by RtspUriGuard at registration; re-validated at view time.
    /// Actor-gated + audited (F4): the URI is never stored with
    /// credentials, so the audit records host/port/path only via
    /// the normalized form the guard rebuilds.</summary>
    public (bool Ok, string Reason) RegisterStreamUri(string assetId, string rtspUri, string actorUserId)
    {
        var now = _now();
        var asset = _register.Get(assetId);
        if (asset is null) return (false, "unknown camera — refused");
        if (!ActorMayAdministerCamera(asset, actorUserId))
        {
            _audit.Append("camera_stream_uri_refused", AuditToken(actorUserId),
                $"camera={AuditToken(asset.AssetId)} reason=actor holds no admin right on the camera's group", now);
            return (false, "actor holds no admin right on the camera's device group — refused");
        }
        var (ok, reason, normalized) = RtspUriGuard.Validate(asset, rtspUri);
        if (!ok)
        {
            _audit.Append("camera_stream_uri_refused", AuditToken(actorUserId),
                $"camera={AuditToken(asset.AssetId)} reason={AuditToken(reason, 96)}", now);
            return (false, reason);
        }
        lock (_gate) _uriByAsset[asset.AssetId] = normalized!;
        _audit.Append("camera_stream_uri_registered", AuditToken(actorUserId),
            $"camera={AuditToken(asset.AssetId)} uri={AuditToken(normalized, 128)}", now);
        return (true, "stream URI registered");
    }

    /// <summary>Register from an ONVIF GetStreamUri response body.</summary>
    public (bool Ok, string Reason) RegisterStreamUriFromOnvif(string assetId, ReadOnlySpan<byte> getStreamUriResponse, string actorUserId)
    {
        var uri = OnvifParsers.ParseStreamUri(getStreamUriResponse);
        if (uri is null) return (false, "ONVIF response carried no stream URI — refused");
        return RegisterStreamUri(assetId, uri, actorUserId);
    }

    // D38-F11 fix: policy facts for a camera carry a NAMESPACED
    // device id ("unmanaged:<assetId>"), never the bare asset id —
    // a device-level policy document written for a MANAGED device
    // that happens to share the id must not silently govern a
    // camera (including its audio key), nor the reverse.
    private IDeviceFacts FactsFor(UnmanagedAsset asset, string deviceGroupId) =>
        StaticDeviceFacts.Of("unmanaged:" + asset.AssetId, asset.ScopeId,
            groups: new[] { deviceGroupId },
            attributes: new Dictionary<string, string> { ["kind"] = asset.Kind });

    private ViewStartResult Refuse(string scopeId, string actor, string assetId, string reason, DateTimeOffset now)
    {
        // Refusals are audited too: an attempted view is a fact.
        // Caller-shaped values enter the detail only as bounded
        // AuditTokens (F8); the reason is service-authored text.
        _audit.Append("camera_view_refused", AuditToken(actor),
            $"camera={AuditToken(assetId)} scope={AuditToken(scopeId)} reason={reason}", now);
        return new ViewStartResult(false, null, reason);
    }

    public ViewStartResult StartView(string scopeId, string actorUserId, string assetId, bool includeAudio = false)
    {
        var now = _now();
        var asset = _register.Get(assetId);
        if (asset is null)
            return Refuse(scopeId, actorUserId, assetId ?? "", "unknown camera — refused", now);
        if (!string.Equals(asset.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse(scopeId, actorUserId, asset.AssetId, "camera is not in this scope — refused (D8 wall)", now);
        if (asset.Kind != UnmanagedAssetKinds.Camera)
            return Refuse(scopeId, actorUserId, asset.AssetId, "asset is not a camera — refused", now);
        // D38-F9 fix: the lifecycle gate. A retired / disposed /
        // in-maintenance / merely-discovered camera is not
        // viewable, whatever its capability, group and URI say.
        if (!string.Equals(asset.LifecycleState, UnmanagedLifecycleStates.Active, StringComparison.OrdinalIgnoreCase))
            return Refuse(scopeId, actorUserId, asset.AssetId,
                $"camera lifecycle state is '{asset.LifecycleState}' — only an active camera is viewable — refused", now);
        if (asset.ViewCapability == CameraViewCapabilities.InventoryOnly)
            return Refuse(scopeId, actorUserId, asset.AssetId,
                $"camera is inventory-only — {(string.IsNullOrWhiteSpace(asset.InventoryOnlyReason) ? "no local view is possible" : asset.InventoryOnlyReason)}", now);
        if (asset.ViewCapability is not (CameraViewCapabilities.Onvif or CameraViewCapabilities.Rtsp))
            return Refuse(scopeId, actorUserId, asset.AssetId, "camera declares no viewable capability — refused", now);

        string? groupId;
        lock (_gate) _groupByAsset.TryGetValue(asset.AssetId, out groupId);
        if (groupId is null)
            return Refuse(scopeId, actorUserId, asset.AssetId, "camera is not filed in any device group — refused (view is a group grant)", now);

        var facts = FactsFor(asset, groupId);
        if (!_policy.IsEnabled(facts, CameraPolicyKeys.ViewingEnabled))
            return Refuse(scopeId, actorUserId, asset.AssetId,
                $"camera viewing is disabled by policy ({CameraPolicyKeys.ViewingEnabled}) — refused", now);
        if (!_roster.UserHasRight(scopeId, actorUserId, groupId, CameraRights.View))
            return Refuse(scopeId, actorUserId, asset.AssetId,
                "actor holds no 'view' grant on the camera's device group — refused", now);

        string? rawUri;
        lock (_gate) _uriByAsset.TryGetValue(asset.AssetId, out rawUri);
        if (rawUri is null)
            return Refuse(scopeId, actorUserId, asset.AssetId, "camera has no registered stream URI — refused", now);
        var (uriOk, uriReason, normalized) = RtspUriGuard.Validate(asset, rawUri);
        if (!uriOk)
            return Refuse(scopeId, actorUserId, asset.AssetId, $"stream URI failed re-validation: {uriReason}", now);

        var audio = false;
        if (includeAudio)
        {
            var audioPolicy = _policy.IsEnabled(facts, CameraPolicyKeys.AudioEnabled);
            var audioGrant = _roster.UserHasRight(scopeId, actorUserId, groupId, CameraRights.Admin);
            if (!audioPolicy || !audioGrant)
                return Refuse(scopeId, actorUserId, asset.AssetId,
                    "audio requested but not authorized: camera audio requires the audio policy AND an admin grant on the camera's group — refused (audio is off by default)", now);
            audio = true;
        }

        var sessionId = Guid.NewGuid().ToString("N");
        // Audit FIRST: the start entry is chained before the stream
        // layer is touched, so no ordering of failures can produce
        // an unaudited live view.
        _audit.Append("camera_view_started", AuditToken(actorUserId),
            $"camera={asset.AssetId} scope={scopeId} group={groupId} session={sessionId} audio={audio}", now);
        bool opened; string detail;
        try
        {
            (opened, detail) = _sink.OpenStream(sessionId, asset.AssetId, normalized!, audio);
        }
        catch (Exception ex)
        {
            // D38-F2 fix: a sink that throws AFTER opening the
            // stream internally must not orphan it — close
            // best-effort, chain the failure, leave no session.
            try { _sink.CloseStream(sessionId); } catch { /* best effort: the failure entry below is the record */ }
            _audit.Append("camera_view_failed", actorUserId,
                $"camera={asset.AssetId} session={sessionId} reason=stream layer threw {ex.GetType().Name}", now);
            return new ViewStartResult(false, null, $"stream layer threw {ex.GetType().Name}");
        }
        if (!opened)
        {
            _audit.Append("camera_view_failed", actorUserId,
                $"camera={asset.AssetId} session={sessionId} reason=stream layer refused: {detail}", now);
            return new ViewStartResult(false, null, $"stream layer refused: {detail}");
        }
        var session = new CameraViewSession(sessionId, scopeId, asset.AssetId, groupId,
            actorUserId, now, null, audio);
        lock (_gate) _sessions[sessionId] = session;
        return new ViewStartResult(true, session, "view started");
    }

    /// <summary>D38-F3 fix: re-check a live session's full gate
    /// chain against CURRENT state. Null = still authorized.
    /// Suspension, grant revocation, policy flips, group moves,
    /// lifecycle changes and audio-gate loss all land here — a
    /// view is a continuing act, not a one-time pass.</summary>
    private string? RevalidateSession(CameraViewSession session, DateTimeOffset now)
    {
        if (now - session.StartedUtc > MaxViewDuration)
            return "maximum view duration reached";
        var asset = _register.Get(session.AssetId);
        if (asset is null) return "camera record removed";
        if (!string.Equals(asset.LifecycleState, UnmanagedLifecycleStates.Active, StringComparison.OrdinalIgnoreCase))
            return $"camera lifecycle state is '{asset.LifecycleState}'";
        string? groupId;
        lock (_gate) _groupByAsset.TryGetValue(asset.AssetId, out groupId);
        if (groupId is null || !string.Equals(groupId, session.DeviceGroupId, StringComparison.OrdinalIgnoreCase))
            return "camera moved out of the session's device group";
        var facts = FactsFor(asset, session.DeviceGroupId);
        if (!_policy.IsEnabled(facts, CameraPolicyKeys.ViewingEnabled))
            return "camera viewing disabled by policy";
        if (!_roster.UserHasRight(session.ScopeId, session.ActorUserId, session.DeviceGroupId, CameraRights.View))
            return "actor no longer holds a 'view' grant (suspended or revoked)";
        if (session.AudioEnabled &&
            (!_policy.IsEnabled(facts, CameraPolicyKeys.AudioEnabled) ||
             !_roster.UserHasRight(session.ScopeId, session.ActorUserId, session.DeviceGroupId, CameraRights.Admin)))
            return "audio authorization no longer holds";
        return null;
    }

    /// <summary>End a session whose authorization evaporated:
    /// mark ended, chain the end WITH the reason, close the
    /// stream. The chain — not the sink — is written first (F2).</summary>
    private void TerminateSession(CameraViewSession session, string reason, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_sessions.TryGetValue(session.SessionId, out var cur) && cur.IsActive)
                _sessions[session.SessionId] = cur with { EndedUtc = now };
            _lastSnapshotBySession.Remove(session.SessionId);
        }
        _audit.Append("camera_view_ended", session.ActorUserId,
            $"camera={session.AssetId} session={session.SessionId} durationSeconds={(long)(now - session.StartedUtc).TotalSeconds} reason={reason}", now);
        try { _sink.CloseStream(session.SessionId); }
        catch (Exception ex)
        {
            _audit.Append("camera_view_close_failed", session.ActorUserId,
                $"camera={session.AssetId} session={session.SessionId} reason=stream layer threw {ex.GetType().Name} on close", now);
        }
    }

    /// <summary>Sweep every active session against current
    /// authorization (F3). The hub duty cycle calls this so a
    /// suspension / revocation / policy flip ends live views even
    /// when nobody touches them; TakeSnapshot also revalidates its
    /// own session on every call. Returns sessions terminated.</summary>
    public int RevalidateActiveViews()
    {
        var now = _now();
        List<CameraViewSession> active;
        lock (_gate) active = _sessions.Values.Where(s => s.IsActive).ToList();
        var terminated = 0;
        foreach (var session in active)
        {
            var failure = RevalidateSession(session, now);
            if (failure is null) continue;
            TerminateSession(session, $"authorization revalidation failed: {failure}", now);
            terminated++;
        }
        return terminated;
    }

    /// <summary>End a view. Only the viewer themselves or a company
    /// admin of the scope may end it. The end entry carries the
    /// duration — the audit record of a view is (who, which camera,
    /// when, how long), complete only at close.</summary>
    public bool StopView(string sessionId, string actorUserId)
    {
        var now = _now();
        CameraViewSession? session;
        lock (_gate) _sessions.TryGetValue(sessionId ?? "", out session);
        if (session is null || !session.IsActive)
        {
            AuditRefusedStop(actorUserId ?? "unknown", sessionId ?? "", "",
                "no active view with this id", now);
            return false;
        }
        var isOwner = string.Equals(session.ActorUserId, actorUserId, StringComparison.OrdinalIgnoreCase);
        if (!isOwner && !_roster.IsCompanyAdmin(session.ScopeId, actorUserId ?? ""))
        {
            AuditRefusedStop(actorUserId ?? "unknown", sessionId ?? "", session.AssetId,
                "actor is neither the viewer nor a company admin", now);
            return false;
        }
        // D38-F2 fix: the session is marked ended and the end
        // entry chained BEFORE the sink is closed — a sink that
        // throws on close can no longer leave a live, unaudited
        // session behind; the close failure is chained after.
        var ended = session with { EndedUtc = now };
        lock (_gate)
        {
            _sessions[sessionId] = ended;
            _lastSnapshotBySession.Remove(sessionId);
        }
        _audit.Append("camera_view_ended", AuditToken(actorUserId),
            $"camera={session.AssetId} session={sessionId} durationSeconds={(long)(now - session.StartedUtc).TotalSeconds}", now);
        try { _sink.CloseStream(sessionId); }
        catch (Exception ex)
        {
            _audit.Append("camera_view_close_failed", AuditToken(actorUserId),
                $"camera={session.AssetId} session={sessionId} reason=stream layer threw {ex.GetType().Name} on close", now);
        }
        return true;
    }

    /// <summary>Take a snapshot from an ACTIVE view owned by the
    /// actor. A snapshot is a view act: no live view, no snapshot.
    /// D38 fixes: the directory is the SERVICE's own snapshot home
    /// (F1 — no caller-supplied baseDir); the session is
    /// REVALIDATED first (F3); snapshots are rate-limited and
    /// retained under a bounded policy (F5); the audit entry is
    /// chained BEFORE the sink writes anything, and a throwing
    /// sink is caught and chained (F2).</summary>
    public (bool Ok, string Reason, string? Path) TakeSnapshot(string sessionId, string actorUserId)
    {
        var now = _now();
        CameraViewSession? session;
        lock (_gate) _sessions.TryGetValue(sessionId ?? "", out session);
        if (session is null || !session.IsActive)
        {
            AuditRefusedSnapshotUnknownSession(actorUserId ?? "", sessionId ?? "", now);
            return (false, "no active view for this session — snapshot refused", null);
        }
        if (!string.Equals(session.ActorUserId, actorUserId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("camera_snapshot_refused", AuditToken(actorUserId),
                $"session={AuditToken(sessionId)} camera={AuditToken(session.AssetId)} reason=snapshot belongs to the view's owner", now);
            return (false, "snapshot belongs to the view's owner — refused", null);
        }
        var revalidation = RevalidateSession(session, now);
        if (revalidation is not null)
        {
            TerminateSession(session, $"authorization revalidation failed: {revalidation}", now);
            _audit.Append("camera_snapshot_refused", AuditToken(actorUserId),
                $"session={AuditToken(sessionId)} camera={AuditToken(session.AssetId)} reason=view authorization no longer holds: {revalidation}", now);
            return (false, $"view authorization no longer holds ({revalidation}) — view ended, snapshot refused", null);
        }
        lock (_gate)
        {
            if (_lastSnapshotBySession.TryGetValue(session.SessionId, out var last) &&
                now - last < MinSnapshotInterval)
            {
                _audit.Append("camera_snapshot_refused", AuditToken(actorUserId),
                    $"session={AuditToken(sessionId)} camera={AuditToken(session.AssetId)} reason=snapshot rate limit ({(int)MinSnapshotInterval.TotalSeconds}s per view)", now);
                return (false, "snapshot rate limit — refused (snapshots are not a time-lapse)", null);
            }
        }
        long sequence;
        lock (_gate) sequence = ++_snapshotSequence;
        var path = SnapshotPathGuard.Resolve(_snapshotBaseDir, session.AssetId, now, sequence);
        if (path is null)
        {
            _audit.Append("camera_snapshot_refused", AuditToken(actorUserId),
                $"session={AuditToken(sessionId)} camera={AuditToken(session.AssetId)} reason=snapshot path refused", now);
            return (false, "snapshot path refused", null);
        }
        // Audit BEFORE capture: a sink that writes the file and
        // then throws still leaves the act on the chain (F2).
        _audit.Append("camera_snapshot", actorUserId,
            $"camera={session.AssetId} session={sessionId} path={Path.GetFileName(path)}", now);
        bool ok; string detail;
        try
        {
            (ok, detail) = _sink.CaptureSnapshot(sessionId, path);
        }
        catch (Exception ex)
        {
            _audit.Append("camera_snapshot_failed", actorUserId,
                $"camera={session.AssetId} session={sessionId} path={Path.GetFileName(path)} reason=stream layer threw {ex.GetType().Name}", now);
            return (false, $"snapshot failed: stream layer threw {ex.GetType().Name}", null);
        }
        if (!ok)
        {
            _audit.Append("camera_snapshot_failed", actorUserId,
                $"camera={session.AssetId} session={sessionId} path={Path.GetFileName(path)} detail={detail}", now);
            return (false, $"snapshot failed: {detail}", null);
        }
        lock (_gate)
        {
            _lastSnapshotBySession[session.SessionId] = now;
            _snapshotFiles.Add((path, now));
            PruneSnapshotFilesLocked(now);
        }
        return (true, "snapshot captured", path);
    }

    /// <summary>F5 retention: snapshot files this service created
    /// are deleted once older than SnapshotRetention, and the
    /// tracked set is capped — oldest first. Deletion is
    /// best-effort; a file already gone is not an error.</summary>
    private void PruneSnapshotFilesLocked(DateTimeOffset now)
    {
        for (var i = _snapshotFiles.Count - 1; i >= 0; i--)
        {
            var expired = now - _snapshotFiles[i].CreatedUtc > SnapshotRetention;
            var overCap = _snapshotFiles.Count > MaxTrackedSnapshots;
            if (!expired && !overCap) continue;
            try { if (File.Exists(_snapshotFiles[i].Path)) File.Delete(_snapshotFiles[i].Path); } catch { /* best effort */ }
            _snapshotFiles.RemoveAt(i);
        }
    }
}
