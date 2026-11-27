using System.Text.Json;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.Sessions;

/// <summary>A TCP tunnel carried by a human session (Block G,
/// G-08 — the census's session form of port forwarding; the
/// pre-programme TcpTunnelModule is the agent-tool form and is a
/// different surface: host-config allowlist, no session, no
/// floor). A tunnel here BELONGS to a session: it opens only
/// inside a live session, under the session's own authority (the
/// floor holder who is driving, or a host-side actor), and it
/// dies with the session — the per-act re-read closes it on the
/// spot if the session has ended or blocked, and the wiring layer
/// sweeps on session change. The record governs; the agent-side
/// byte mover (the Phase2 listener) is the mechanism it governs
/// and may only run tunnels this service has opened.</summary>
public sealed record SessionTunnel(
    string Id,
    string SessionId,
    string TargetHost,
    int TargetPort,
    int ListenPort,
    string State,
    string OpenedByUserId,
    DateTimeOffset OpenedUtc,
    DateTimeOffset? ClosedUtc);

public sealed record SessionTunnelEvent(
    DateTimeOffset Utc, string Kind, string TunnelId, string? ActorUserId, string Detail);

public sealed class SessionTunnelService
{
    /// <summary>Valid tunnel states: open | closed (terminal).</summary>
    public static readonly IReadOnlySet<string> ValidStates =
        new HashSet<string> { "open", "closed" };

    private readonly SessionService _sessions;
    private readonly RosterService _roster;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly Action<string, string?, string>? _auditSink;
    private readonly HashSet<string>? _allowedTargets;
    private readonly Dictionary<string, SessionTunnel> _tunnels = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SessionTunnelEvent> _events = new();
    private readonly object _gate = new();

    /// <param name="featureGate">TOTAL POLICY CONTROL gate,
    /// SCOPE-AWARE (scopeId, featureKey) — D38 review F2.</param>
    /// <param name="auditSink">Optional chained-audit sink
    /// (kind, actor, detail): every recorded act is also appended
    /// to the product's hash-chained audit by the wiring layer
    /// (D38 review F1). Null = in-memory events only.</param>
    /// <param name="allowedTargets">The host-config destination
    /// ALLOWLIST (Block H, the D38 F9 remainder): "host:port"
    /// entries, host matched case-insensitively — TcpTunnelModule
    /// parity as a managed list. NULL = not configured on this
    /// host (the pivot blocklist remains the control, the Block G
    /// posture). NON-NULL (even empty) = enforced: Open refuses
    /// and Import restores-as-closed any destination not listed.</param>
    public SessionTunnelService(SessionService sessions, RosterService roster,
        Func<string, string, PolicyVerdict>? featureGate = null,
        Action<string, string?, string>? auditSink = null,
        IReadOnlySet<string>? allowedTargets = null)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _featureGate = featureGate;
        _auditSink = auditSink;
        _allowedTargets = allowedTargets is null
            ? null
            : new HashSet<string>(allowedTargets.Select(NormalizeTarget), StringComparer.Ordinal);
    }

    private static string NormalizeTarget(string entry)
    {
        var e = (entry ?? "").Trim();
        var colon = e.LastIndexOf(':');
        return colon > 0 ? e[..colon].ToLowerInvariant() + e[colon..] : e.ToLowerInvariant();
    }

    private bool DestinationAllowed(string host, int port) =>
        _allowedTargets is null || _allowedTargets.Contains($"{host.ToLowerInvariant()}:{port}");

    public event Action? Changed;
    public IReadOnlyList<SessionTunnelEvent> Events { get { lock (_gate) return _events.ToList(); } }

    private bool FeatureAllowed(Session session) =>
        _featureGate?.Invoke(session.ScopeId, PolicyFeatures.TcpTunnel).Allowed ?? true;

    private void RecordLocked(string kind, SessionTunnel tunnel, string? actor, string detail)
    {
        _events.Add(new SessionTunnelEvent(DateTimeOffset.UtcNow, kind, tunnel.Id, actor, detail));
        _auditSink?.Invoke(kind, actor, detail);
        Changed?.Invoke();
    }

    /// <summary>Who may open/close a tunnel on a session: the
    /// floor holder (a live, non-suspended participant — a stale
    /// holder row confers nothing, the F4 rule) or a host-side
    /// actor under the session model's own rule. OPENING also
    /// re-reads the AF3 "use" grant (Block H D38 fix F9): a floor
    /// holder whose grant on the host device's group was revoked
    /// mid-session opens nothing — the same per-act re-read the
    /// session's own surfaces (blank, input block, calls) already
    /// perform, now covering the bigger power. Host-side actors
    /// are exempt, exactly as in CanEnableSurfaceLocked. CLOSING
    /// never re-reads the grant: the escape direction cannot
    /// depend on the right whose loss is being escaped.</summary>
    private bool CanDriveLocked(Session session, string? actorUserId, bool requireUseGrant = true)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (_sessions.IsHostSideActor(session.Id, actorUserId)) return true;
        var holder = _sessions.ListParticipants(session.Id).FirstOrDefault(p =>
            p.Floor == "holds" && string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (holder is null) return false;
        var user = _roster.GetUser(session.ScopeId, actorUserId);
        if (user is null || user.Suspended) return false;
        return !requireUseGrant || _sessions.HoldsUseGrant(session.Id, actorUserId);
    }

    /// <summary>The opener's CURRENT authority over this tunnel,
    /// re-read live (F9, second half): host-side, or still the
    /// floor holder still holding the "use" grant. Anything less
    /// and the tunnel's reason to exist is gone.</summary>
    private bool OpenerAuthorityLiveLocked(Session session, SessionTunnel tunnel) =>
        CanDriveLocked(session, tunnel.OpenedByUserId);

    /// <summary>The liveness re-read, run before every act AND
    /// every read (D38 review F5: readers — ListOpen above all,
    /// the byte mover's source — must never see a stale "open"):
    /// a tunnel whose session is no longer active/paused, or
    /// whose opener is no longer a live user of the scope
    /// (suspended/removed authority confers nothing), is closed
    /// on the spot, recorded in both event lists, and the act
    /// refuses. A tunnel never outlives its session or its
    /// opener's authority by so much as one operation.</summary>
    private bool EnforceSessionLiveLocked(SessionTunnel tunnel)
    {
        if (tunnel.State == "closed") return false;
        var session = _sessions.GetSession(tunnel.SessionId);
        var opener = session is null ? null : _roster.GetUser(session.ScopeId, tunnel.OpenedByUserId);
        var openerLive = opener is not null && !opener.Suspended;
        var sessionLive = session is not null && session.State is "active" or "paused";
        // The full keep-open condition (Block H D38 fixes F7+F9):
        // session live, opener live, the tcp_tunnel POLICY toggle
        // still allowed for the session's scope (F7 — a disable
        // that lands while the Core is down, or whose reload sweep
        // never ran, still ends the tunnel at the next read/act
        // instead of the tunnel staying open indefinitely), and
        // the opener's floor/grant authority still live (F9).
        if (sessionLive && openerLive && FeatureAllowed(session!) &&
            OpenerAuthorityLiveLocked(session!, tunnel)) return false;
        var kind = !sessionLive || !openerLive
            ? "tunnel_closed_session_gone"
            : !FeatureAllowed(session!)
                ? "tunnel_closed_policy"
                : "tunnel_closed_authority_gone";
        var detail = !sessionLive
            ? "Tunnel closed: its session is no longer live."
            : !openerLive
                ? "Tunnel closed: its opener is no longer a live user of the scope."
                : !FeatureAllowed(session!)
                    ? "Tunnel closed: policy no longer allows tcp_tunnel for this scope."
                    : "Tunnel closed: its opener no longer holds the floor and the 'use' grant.";
        _tunnels[tunnel.Id] = tunnel with { State = "closed", ClosedUtc = DateTimeOffset.UtcNow };
        RecordLocked(kind, _tunnels[tunnel.Id], null, detail);
        if (session is not null)
            _sessions.AppendEvent(session.Id, "tunnel_closed", null, tunnel.Id,
                "Session tunnel closed: session, policy, or opener authority no longer live.");
        return true;
    }

    /// <summary>A target is a DESTINATION: a non-empty host name
    /// or IP literal with no whitespace/control characters, never
    /// a wildcard bind address (0.0.0.0 / :: are listen addresses,
    /// not destinations — as targets they are configuration
    /// errors, refused rather than reinterpreted).</summary>
    public static bool IsValidTargetHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        var h = host.Trim();
        if (h.Length > 255) return false;
        if (h.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return false;
        if (h is "0.0.0.0" or "::" or "*") return false;
        // BD-SHARED-SESSION F3: the unspecified addresses in every
        // notation are listen addresses, never destinations.
        if (System.Net.IPAddress.TryParse(h.Trim('[', ']'), out var ip) &&
            (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)))
            return false;
        return true;
    }

    /// <summary>Open a tunnel inside a live session. Null on
    /// refusal: policy-disabled (TOTAL POLICY CONTROL, key
    /// "tcp_tunnel"), an unknown or non-live session, an actor who
    /// neither holds the floor nor is host-side, an AI actor (D38
    /// review F9: an AI's leash covers screen control when granted
    /// the floor — a network pivot is a different power and is
    /// never an AI's), a pivot target (loopback / link-local /
    /// localhost — F9), a target outside the host-config
    /// destination allowlist when one is configured (Block H), an
    /// invalid target host, a target
    /// port outside 1–65535, a listen port that is neither 0 (the
    /// agent assigns) nor 1024–65535, a listen port already open
    /// on this session, or an identical open tunnel (same session
    /// + target + listen port).</summary>
    public SessionTunnel? Open(string sessionId, string actorUserId,
        string targetHost, int targetPort, int listenPort)
    {
        if (!IsValidTargetHost(targetHost)) return null;
        if (IsPivotTarget(targetHost)) return null;
        if (targetPort is < 1 or > 65535) return null;
        if (listenPort != 0 && listenPort is < 1024 or > 65535) return null;
        lock (_gate)
        {
            var session = _sessions.GetSession(sessionId);
            if (session is null) return null;
            if (!FeatureAllowed(session)) return null;
            if (session.State is not ("active" or "paused")) return null;
            var actor = _roster.GetUser(session.ScopeId, actorUserId);
            if (actor is null || actor.Suspended) return null;
            if (string.Equals(actor.Kind, "ai", StringComparison.OrdinalIgnoreCase)) return null;
            if (!CanDriveLocked(session, actorUserId)) return null;
            var host = targetHost.Trim();
            if (!DestinationAllowed(host, targetPort)) return null; // host-config allowlist, when configured (Block H)
            foreach (var t in _tunnels.Values.Where(t =>
                         string.Equals(t.SessionId, session.Id, StringComparison.OrdinalIgnoreCase) &&
                         t.State == "open"))
            {
                if (listenPort != 0 && t.ListenPort == listenPort) return null;
                if (t.ListenPort == listenPort &&
                    string.Equals(t.TargetHost, host, StringComparison.OrdinalIgnoreCase) &&
                    t.TargetPort == targetPort) return null;
            }
            var tunnel = new SessionTunnel(Guid.NewGuid().ToString("N"), session.Id, host,
                targetPort, listenPort, "open", actorUserId, DateTimeOffset.UtcNow, null);
            _tunnels[tunnel.Id] = tunnel;
            RecordLocked("tunnel_opened", tunnel, actorUserId,
                $"Tunnel opened: :{listenPort} → {host}:{targetPort} in session {session.Id}.");
            _sessions.AppendEvent(session.Id, "tunnel_opened", actorUserId, tunnel.Id,
                $"TCP tunnel opened to {host}:{targetPort} (listen :{listenPort}).");
            return tunnel;
        }
    }

    /// <summary>Close a tunnel. The opener, the current floor
    /// holder, or a host-side actor may close; an already-closed
    /// tunnel refuses. The session-liveness re-read runs first —
    /// closing a tunnel on a dead session reports the sweep's
    /// close instead (false: this act did not close it).</summary>
    public bool Close(string tunnelId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_tunnels.TryGetValue(tunnelId ?? "", out var tunnel)) return false;
            if (EnforceSessionLiveLocked(tunnel)) return false;
            tunnel = _tunnels[tunnel.Id];
            if (tunnel.State == "closed") return false;
            var session = _sessions.GetSession(tunnel.SessionId);
            if (session is null) return false;
            if (!string.Equals(actorUserId, tunnel.OpenedByUserId, StringComparison.OrdinalIgnoreCase) &&
                !CanDriveLocked(session, actorUserId, requireUseGrant: false)) return false;
            _tunnels[tunnel.Id] = tunnel with { State = "closed", ClosedUtc = DateTimeOffset.UtcNow };
            RecordLocked("tunnel_closed", _tunnels[tunnel.Id], actorUserId, "Tunnel closed.");
            _sessions.AppendEvent(session.Id, "tunnel_closed", actorUserId, tunnel.Id,
                "Session tunnel closed.");
            return true;
        }
    }

    /// <summary>The device-presence close (Block H D38 fix F10):
    /// the person physically at this machine can close ANY open
    /// tunnel — the panel's stop, with no typed roster id. A
    /// STOP-only power (§7.10 fail-safe direction), recorded
    /// under the reserved actor "device-console", never under a
    /// claimed identity borrowed from another card's text box
    /// (the panel's tunnel card used to send the WAKE card's
    /// actor). Reachable only from inside the host process (the
    /// Core's laptop-UI IPC channel); not an MCP surface. The
    /// session-liveness re-read still runs first: a tunnel the
    /// sweep already closed reports the sweep's close.</summary>
    public bool CloseFromDevice(string tunnelId)
    {
        lock (_gate)
        {
            if (!_tunnels.TryGetValue(tunnelId ?? "", out var tunnel)) return false;
            if (EnforceSessionLiveLocked(tunnel)) return false;
            tunnel = _tunnels[tunnel.Id];
            if (tunnel.State == "closed") return false;
            var session = _sessions.GetSession(tunnel.SessionId);
            if (session is null) return false;
            _tunnels[tunnel.Id] = tunnel with { State = "closed", ClosedUtc = DateTimeOffset.UtcNow };
            RecordLocked("tunnel_closed", _tunnels[tunnel.Id], StandaloneTransferService.DeviceConsoleActor,
                "Tunnel closed from the device console by the person at this machine (device-presence stop, §7.10).");
            _sessions.AppendEvent(session.Id, "tunnel_closed", StandaloneTransferService.DeviceConsoleActor, tunnel.Id,
                "Session tunnel closed from the device console.");
            return true;
        }
    }

    /// <summary>Policy-change TEARDOWN sweep (Block H — the D38
    /// F6 remainder): when a policy reload disables tcp_tunnel,
    /// every open tunnel on a session of that scope closes on the
    /// spot, recorded in both event lists. A tunnel is a
    /// continuing network effect; a disable that left it running
    /// would be a label, not a control. Returns the number
    /// closed.</summary>
    public int SweepPolicyTeardown(string scopeId, Func<string, bool> featureDisabled)
    {
        if (!featureDisabled(PolicyFeatures.TcpTunnel)) return 0;
        lock (_gate)
        {
            var count = 0;
            foreach (var tunnel in _tunnels.Values.Where(t => t.State == "open").ToList())
            {
                var session = _sessions.GetSession(tunnel.SessionId);
                if (session is null ||
                    !string.Equals(session.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase))
                    continue;
                _tunnels[tunnel.Id] = tunnel with { State = "closed", ClosedUtc = DateTimeOffset.UtcNow };
                RecordLocked("tunnel_closed_policy", _tunnels[tunnel.Id], "policy",
                    "Tunnel closed: a policy change disabled tcp_tunnel for this scope.");
                _sessions.AppendEvent(session.Id, "tunnel_closed", "policy", tunnel.Id,
                    "Session tunnel closed: a policy change disabled tcp_tunnel for this scope.");
                count++;
            }
            return count;
        }
    }

    /// <summary>Close every open tunnel on a session — the wiring
    /// layer's sweep when a session ends or blocks. Returns the
    /// number closed.</summary>
    public int CloseForSession(string sessionId, string? actorUserId = null)
    {
        lock (_gate)
        {
            var count = 0;
            foreach (var tunnel in _tunnels.Values.Where(t =>
                         string.Equals(t.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase) &&
                         t.State == "open").ToList())
            {
                _tunnels[tunnel.Id] = tunnel with { State = "closed", ClosedUtc = DateTimeOffset.UtcNow };
                RecordLocked("tunnel_closed_session_end", _tunnels[tunnel.Id], actorUserId,
                    "Tunnel closed by session-end sweep.");
                count++;
            }
            return count;
        }
    }

    /// <summary>Pivot targets (D38 review F9): destinations a
    /// remote session must never be able to reach THROUGH the
    /// host — the host's own loopback, link-local space, and the
    /// localhost name. A tunnel exists to reach the host's LAN;
    /// the host itself is reached by the session, not by a tunnel
    /// behind the session's back.</summary>
    public static bool IsPivotTarget(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        var h = host.Trim().TrimEnd('.').Trim('[', ']').ToLowerInvariant();
        // Name forms of loopback (BD-SHARED-SESSION F3): "localhost",
        // any "*.localhost" subdomain, and a trailing-dot FQDN form.
        if (h is "localhost" || h.EndsWith(".localhost")) return true;
        // Alternate IPv4 notations some resolvers accept (decimal /
        // hex integer forms of 127.0.0.0/8 or 0.0.0.0): refuse the
        // whole bare-integer and 0x-prefixed shapes as destinations —
        // no legitimate LAN destination is written that way.
        if (h.All(char.IsDigit) && h.Length > 3) return true;
        if (h.StartsWith("0x")) return true;
        if (System.Net.IPAddress.TryParse(h, out var ip))
            return IsPivotAddress(ip);
        return false;
    }

    /// <summary>BD-SHARED-SESSION F3: the parsed-address pivot test —
    /// loopback (incl. IPv4-mapped IPv6, unmapped first), link-local
    /// (169.254/16 and fe80::/10 — the whole range, not the "fe80:"
    /// string prefix), and the unspecified addresses.</summary>
    public static bool IsPivotAddress(System.Net.IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (System.Net.IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)) return true;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return b[0] == 169 && b[1] == 254;
        return b.Length == 16 && b[0] == 0xFE && (b[1] & 0xC0) == 0x80;
    }

    /// <summary>BD-SHARED-SESSION F3, connect-time half: the byte
    /// mover resolves the target name and re-checks EVERY resolved
    /// address through this before connecting, so a DNS name that
    /// resolves (or rebinds) to loopback/link-local is refused at
    /// connect time, not merely at open time. An empty resolution
    /// fails closed.</summary>
    public static bool IsResolvedPivotTarget(IEnumerable<System.Net.IPAddress> resolved)
    {
        var any = false;
        foreach (var ip in resolved) { any = true; if (IsPivotAddress(ip)) return true; }
        return !any;
    }

    public SessionTunnel? GetTunnel(string? tunnelId)
    {
        if (string.IsNullOrWhiteSpace(tunnelId)) return null;
        lock (_gate)
        {
            if (!_tunnels.TryGetValue(tunnelId, out var t)) return null;
            EnforceSessionLiveLocked(t); // F5: reads never see stale "open"
            return _tunnels[t.Id];
        }
    }

    public IReadOnlyList<SessionTunnel> ListTunnels(string sessionId)
    {
        lock (_gate)
        {
            foreach (var t in _tunnels.Values.Where(t =>
                         string.Equals(t.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase) &&
                         t.State == "open").ToList())
                EnforceSessionLiveLocked(t);
            return _tunnels.Values
                .Where(t => string.Equals(t.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    public IReadOnlyList<SessionTunnel> ListOpen()
    {
        lock (_gate)
        {
            foreach (var t in _tunnels.Values.Where(t => t.State == "open").ToList())
                EnforceSessionLiveLocked(t);
            return _tunnels.Values.Where(t => t.State == "open").ToList();
        }
    }

    // ---- persistence ------------------------------------------------------

    private sealed record TunnelDto(string Id, string SessionId, string TargetHost, int TargetPort,
        int ListenPort, string State, string OpenedByUserId, DateTimeOffset OpenedUtc,
        DateTimeOffset? ClosedUtc);

    private sealed record EventDto(DateTimeOffset Utc, string Kind, string TunnelId,
        string? ActorUserId, string Detail);

    private sealed record StoreDto(TunnelDto[] Tunnels, EventDto[]? Events);

    public string ExportJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new StoreDto(
                _tunnels.Values.Select(t => new TunnelDto(
                    t.Id, t.SessionId, t.TargetHost, t.TargetPort, t.ListenPort, t.State,
                    t.OpenedByUserId, t.OpenedUtc, t.ClosedUtc)).ToArray(),
                _events.Select(e => new EventDto(e.Utc, e.Kind, e.TunnelId, e.ActorUserId, e.Detail)).ToArray()));
    }

    /// <summary>Restore, re-validated: malformed entries drop;
    /// an "open" tunnel restores open ONLY if its session exists
    /// and is live in the session store right now — anything else
    /// restores closed (a restart leaves nothing live behind a
    /// record, the F11 rule applied to tunnels).</summary>
    public int ImportJson(string json)
    {
        TunnelDto[]? dtos;
        EventDto[]? eventDtos = null;
        try
        {
            var store = JsonSerializer.Deserialize<StoreDto>(json);
            dtos = store?.Tunnels;
            eventDtos = store?.Events;
        }
        catch { dtos = null; }
        if (dtos is null)
        {
            // The pre-F1 shape: a bare tunnel array.
            try { dtos = JsonSerializer.Deserialize<TunnelDto[]>(json); }
            catch { return 0; }
        }
        if (dtos is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in eventDtos ?? Array.Empty<EventDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Kind) ||
                    string.IsNullOrWhiteSpace(dto.TunnelId)) continue;
                _events.Add(new SessionTunnelEvent(dto.Utc, dto.Kind, dto.TunnelId,
                    dto.ActorUserId, dto.Detail ?? ""));
            }
            foreach (var dto in dtos)
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    string.IsNullOrWhiteSpace(dto.SessionId) ||
                    string.IsNullOrWhiteSpace(dto.OpenedByUserId)) continue;
                if (!IsValidTargetHost(dto.TargetHost)) continue;
                if (IsPivotTarget(dto.TargetHost)) continue; // F9 holds on import too
                if (dto.TargetPort is < 1 or > 65535) continue;
                if (dto.ListenPort != 0 && dto.ListenPort is < 1024 or > 65535) continue;
                var state = (dto.State ?? "").Trim().ToLowerInvariant();
                if (!ValidStates.Contains(state)) continue;
                if (_tunnels.ContainsKey(dto.Id)) continue;
                var closedUtc = dto.ClosedUtc;
                if (state == "open")
                {
                    var session = _sessions.GetSession(dto.SessionId);
                    if (session is null || session.State is not ("active" or "paused"))
                    {
                        state = "closed";
                        closedUtc ??= DateTimeOffset.UtcNow;
                    }
                    else if (!FeatureAllowed(session))
                    {
                        // F7: the tcp_tunnel toggle is re-read at
                        // import too — a policy disable that landed
                        // while the Core was down must not restore
                        // a tunnel open underneath itself.
                        state = "closed";
                        closedUtc ??= DateTimeOffset.UtcNow;
                    }
                    else if (_roster.GetUser(session.ScopeId, dto.OpenedByUserId) is not { Suspended: false } openerUser ||
                             string.Equals(openerUser.Kind, "ai", StringComparison.OrdinalIgnoreCase))
                    {
                        // F7/F9: import repeats Open's refusals —
                        // a dead/suspended opener, and above all
                        // an AI opener (Open refuses AI actors
                        // outright), restores closed, never open.
                        state = "closed";
                        closedUtc ??= DateTimeOffset.UtcNow;
                    }
                    else if (!DestinationAllowed(dto.TargetHost.Trim(), dto.TargetPort))
                    {
                        // The allowlist is host config NOW: a
                        // tunnel the current config no longer
                        // lists restores closed, never open.
                        state = "closed";
                        closedUtc ??= DateTimeOffset.UtcNow;
                    }
                }
                if (state == "closed" && closedUtc is null) closedUtc = dto.OpenedUtc;
                _tunnels[dto.Id] = new SessionTunnel(dto.Id, dto.SessionId, dto.TargetHost.Trim(),
                    dto.TargetPort, dto.ListenPort, state, dto.OpenedByUserId,
                    dto.OpenedUtc, closedUtc);
                restored++;
            }
        }
        return restored;
    }
}
