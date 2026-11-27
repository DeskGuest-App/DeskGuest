namespace DeskGuest.Shared.Security;

/// <summary>
/// W97 / S09(b) — the AI connection-path policy (Jacob,
/// 2026-11-23): per pairing, the owner chooses HOW the paired AI
/// may connect. Three modes:
///   AUTO            — the full transports menu; best working
///                     path, silent failover, no re-pairing on
///                     switch.
///   AUTO, RESTRICTED — the owner picks a SUBSET of transports;
///                     Auto works only within it.
///   MANUAL          — one pinned path; the connection uses
///                     exactly that.
/// Standing rules (FEATURES §8): the app always shows the rung
/// the agent is ACTUALLY on; the mode lives on the agent card
/// beside the access slider (set at pairing, re-tunable, changes
/// audited); a restricted subset with no working path reports
/// that truthfully — it NEVER silently widens. Rung restriction
/// per agent is a security control, not just convenience.
///
/// This type is the ONE model: the pairing store carries a
/// <see cref="ConnectionPathSetting"/>, the inbound connection
/// choke point (McpHandler, fed the arrival lane by
/// LaneHostManager) enforces <see cref="ConnectionPathPolicy.Allows"/>,
/// the pairing exchange refuses a code whose setting excludes
/// the arrival lane, and the outbound failover engine's order
/// can be narrowed by <see cref="ConnectionPathPolicy.FilterOrder"/>
/// under the same never-widen rule.
/// </summary>
public enum ConnectionMode
{
    Auto = 0,
    AutoRestricted = 1,
    Manual = 2,
    // W107 (W106-verified C5): the FAIL-CLOSED restore state for a
    // stored record whose connection fields are PRESENT but do not
    // parse/validate. Never owner-selectable (Validate refuses it,
    // Parse never produces it): it exists so a corrupt restriction
    // restores as "refuse every rung until the owner re-sets it"
    // instead of the pre-W107 fail-open AUTO. The corrupt record's
    // original fields are preserved verbatim on the pairing (see
    // Pairing.ConnectionCorrupt) and are never overwritten by an
    // export; the owner repairs by setting the path again, which
    // clears the state.
    CorruptRefused = 3,
}

/// <summary>One pairing's connection-path setting. AllowedRungs
/// is read only in AutoRestricted; PinnedRung only in Manual.
/// Rung ids are the product's real transport ids (see
/// <see cref="ConnectionPathPolicy.Rungs"/>).</summary>
public sealed record ConnectionPathSetting(
    ConnectionMode Mode = ConnectionMode.Auto,
    IReadOnlySet<string>? AllowedRungs = null,
    string? PinnedRung = null)
{
    /// <summary>The default every pre-W97 pairing carries: AUTO.</summary>
    public static readonly ConnectionPathSetting DefaultAuto = new();

    /// <summary>W107: the fail-closed setting a present-but-corrupt
    /// stored record restores as. Allows() refuses every rung under
    /// it and FilterOrder narrows to nothing — the pairing cannot
    /// connect on ANY path until the owner re-sets the setting.</summary>
    public static readonly ConnectionPathSetting CorruptRefusedSetting = new(ConnectionMode.CorruptRefused);

    public IReadOnlySet<string> AllowedOrEmpty =>
        AllowedRungs is null
            ? new HashSet<string>()
            : new HashSet<string>(AllowedRungs.Select(NormalizeRung).Where(r => r.Length > 0));

    public string? PinOrNull =>
        string.IsNullOrWhiteSpace(PinnedRung) ? null : NormalizeRung(PinnedRung);

    public static string NormalizeRung(string? rung) => (rung ?? "").Trim().ToLowerInvariant();
}

public static class ConnectionPathPolicy
{
    /// <summary>One real transport: its rung id and its plain
    /// name for the owner surfaces. The ids are the tree's own —
    /// the failover engine's rungs (lan / hub / mesh / netbird /
    /// ipv6 / ownpath / relay / tor, the ConnectionDoctor list) plus loopback,
    /// the local-only lane the host also binds.</summary>
    public sealed record RungInfo(string Id, string PlainName);

    public static readonly IReadOnlyList<RungInfo> Rungs = new[]
    {
        new RungInfo("mesh", "Private mesh (Tailscale)"),
        new RungInfo("netbird", "Private mesh (NetBird)"),
        new RungInfo("lan", "Home network (LAN)"),
        new RungInfo("hub", "Company hub"),
        new RungInfo("ipv6", "Direct IPv6"),
        new RungInfo("ownpath", "Direct public IP"),
        new RungInfo("relay", "Public relay (sealed)"),
        new RungInfo("tor", "Tor (hidden service)"),
        new RungInfo("loopback", "This PC only (loopback)"),
    };

    public static bool IsKnownRung(string? rung) =>
        Rungs.Any(r => r.Id == ConnectionPathSetting.NormalizeRung(rung));

    public static string PlainName(string? rung)
    {
        var id = ConnectionPathSetting.NormalizeRung(rung);
        return Rungs.FirstOrDefault(r => r.Id == id)?.PlainName ?? id;
    }

    /// <summary>The host listener lane a request arrived on, as a
    /// rung id: LaneHostManager's lane names are the
    /// LaneSupervisor's LaneKind names ("Tailscale" / "Lan") plus
    /// "loopback". The tailnet lane carries the mesh rung.</summary>
    public static string RungForLane(string? laneName) => (laneName ?? "").Trim().ToLowerInvariant() switch
    {
        "tailscale" => "mesh",
        "lan" => "lan",
        "loopback" => "loopback",
        _ => ConnectionPathSetting.NormalizeRung(laneName),
    };

    /// <summary>May a connection for this pairing travel over
    /// <paramref name="rungId"/>? AUTO: any rung. RESTRICTED:
    /// only the owner's subset. MANUAL: only the pin. An unknown
    /// rung id is never allowed under a restriction, and AUTO
    /// still requires a real rung (an empty arrival claim is not
    /// a path).</summary>
    public static bool Allows(ConnectionPathSetting? setting, string? rungId)
    {
        var s = setting ?? ConnectionPathSetting.DefaultAuto;
        var rung = ConnectionPathSetting.NormalizeRung(rungId);
        if (rung.Length == 0) return false;
        return s.Mode switch
        {
            ConnectionMode.Auto => true,
            ConnectionMode.AutoRestricted => s.AllowedOrEmpty.Contains(rung),
            ConnectionMode.Manual => s.PinOrNull is { } pin && pin == rung,
            // CorruptRefused (W107) and any unknown mode: NO rung —
            // fail closed on every path.
            _ => false,
        };
    }

    /// <summary>Narrow an ordered rung list (the failover
    /// engine's resolved order) to what this pairing's setting
    /// permits, preserving order. NEVER widens: rungs outside
    /// the setting are dropped, never added; an empty result
    /// stays empty — the caller reports "no working path in the
    /// allowed set" rather than falling back to the full menu.</summary>
    public static IReadOnlyList<string> FilterOrder(
        IEnumerable<string> resolvedOrder, ConnectionPathSetting? setting)
    {
        var s = setting ?? ConnectionPathSetting.DefaultAuto;
        var order = resolvedOrder
            .Select(ConnectionPathSetting.NormalizeRung)
            .Where(r => r.Length > 0)
            .ToList();
        return s.Mode switch
        {
            ConnectionMode.Auto => order,
            ConnectionMode.AutoRestricted => order.Where(r => s.AllowedOrEmpty.Contains(r)).ToList(),
            ConnectionMode.Manual => s.PinOrNull is { } pin
                ? order.Where(r => r == pin).ToList()
                : new List<string>(),
            _ => new List<string>(),
        };
    }

    /// <summary>Validate a proposed setting at the store: known
    /// mode, known rungs only, a restricted subset holds at
    /// least one rung, a manual pin names exactly one known
    /// rung. Returns null when valid, else the refusal reason.</summary>
    public static string? Validate(ConnectionPathSetting? setting)
    {
        if (setting is null) return "no connection setting was supplied — refused";
        if (!Enum.IsDefined(setting.Mode)) return "unknown connection mode — refused";
        // W107: the fail-closed restore state is not a setting an
        // owner (or a caller) may propose — the repair is choosing
        // a real mode, never re-asserting the corrupt state.
        if (setting.Mode == ConnectionMode.CorruptRefused)
            return "the saved connection setting could not be read — choose how this helper connects again (refused)";
        switch (setting.Mode)
        {
            case ConnectionMode.AutoRestricted:
                var allowed = setting.AllowedOrEmpty;
                if (allowed.Count == 0)
                    return "restricted mode needs at least one allowed path — refused";
                foreach (var r in allowed)
                    if (!IsKnownRung(r)) return $"unknown transport '{r}' — refused";
                return null;
            case ConnectionMode.Manual:
                if (setting.PinOrNull is not { } pin)
                    return "manual mode needs one pinned path — refused";
                if (!IsKnownRung(pin)) return $"unknown transport '{pin}' — refused";
                return null;
            default:
                return null;
        }
    }

    /// <summary>The setting in one plain line, for cards and
    /// audit entries.</summary>
    public static string Describe(ConnectionPathSetting? setting)
    {
        var s = setting ?? ConnectionPathSetting.DefaultAuto;
        return s.Mode switch
        {
            ConnectionMode.Auto => "Auto — any working path",
            ConnectionMode.AutoRestricted =>
                "Auto, restricted to " + string.Join(", ",
                    s.AllowedOrEmpty.OrderBy(r => r).Select(PlainName)),
            ConnectionMode.Manual => "Manual — only " + PlainName(s.PinOrNull),
            // W107: never describe the corrupt state as AUTO (or as
            // any chosen setting) — the surface says it needs the
            // owner's attention, in those words.
            ConnectionMode.CorruptRefused =>
                "Needs attention — the saved connection setting could not be read, so this helper cannot connect until you set it again",
            _ => "Unknown mode",
        };
    }

    /// <summary>Parse the wire/UI shape ({mode, allowedRungs,
    /// pinnedRung}) into a setting. Mode names: "auto",
    /// "restricted", "manual" (the enum names also parse).
    /// Returns null on an unparseable mode — the caller refuses
    /// rather than guessing.</summary>
    public static ConnectionPathSetting? Parse(string? mode, IEnumerable<string>? allowedRungs, string? pinnedRung)
    {
        var m = (mode ?? "").Trim().ToLowerInvariant() switch
        {
            "auto" => ConnectionMode.Auto,
            "restricted" or "autorestricted" or "auto_restricted" => ConnectionMode.AutoRestricted,
            "manual" => ConnectionMode.Manual,
            _ => (ConnectionMode?)null,
        };
        if (m is null) return null;
        return new ConnectionPathSetting(
            m.Value,
            allowedRungs is null ? null : new HashSet<string>(allowedRungs.Select(NormalizeRung).Where(r => r.Length > 0)),
            string.IsNullOrWhiteSpace(pinnedRung) ? null : NormalizeRung(pinnedRung));
    }

    private static string NormalizeRung(string r) => ConnectionPathSetting.NormalizeRung(r);
}
