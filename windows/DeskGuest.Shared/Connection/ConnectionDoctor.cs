using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DeskGuest.Shared.Connection;

// =====================================================================
// U6 — Connection doctor (UNION spec, log-union-verify.md).
//
// Answers ONE question: "why can't I connect?" — from facts the
// product already has about itself. DIAGNOSTIC ONLY, by construction:
//  * No sockets, no pings, no STUN, no DNS — this file contains no
//    network I/O API at all. It classifies address STRINGS it is
//    handed and reads interface facts the OS already reports.
//  * No mutation — every input is an immutable snapshot record; the
//    doctor holds no reference to any supervisor, rung, or store it
//    could change. Building a report cannot bind, unbind, retry, or
//    reconfigure anything.
//  * No target parameter — there is no way to aim the doctor at an
//    arbitrary address. A peer address may be CLASSIFIED (parsed,
//    never contacted) only when the caller already knows it from
//    enrollment/discovery; classification sends nothing.
//  * Honest verdicts — a rung is "reachable" ONLY on positive
//    evidence (a bound lane, or a recorded successful attempt).
//    Configured / dormant / registered is never reported as healthy.
//  * NAT depth honesty — without an owner-configured external
//    endpoint (STUN-like), the depth of NAT upstream of the local
//    interface cannot be observed. The report says so in plain
//    language instead of guessing: classification is from local
//    interface/address facts only.
// =====================================================================

/// <summary>What kind of address a string is. Parse-only.</summary>
public enum AddressClass
{
    NotAnAddress, Loopback, LinkLocal, PrivateRfc1918, TailnetCgnat,
    CarrierGradeNat, Public, Ipv6Global, Ipv6PrivateOrLocal, Ipv6Other,
    /// <summary>BD-SHARED-SESSION F9: IANA special-purpose ranges that
    /// are not public reachability (0/8, 192.0.2/24 TEST-NET-1,
    /// 198.18/15 benchmarking, 224/4 multicast and 240/4 reserved).</summary>
    Reserved
}

/// <summary>This (or the peer's) NAT situation, as far as local facts
/// can honestly say. <see cref="Hostile"/> = the D18 corner's kind of
/// NAT: carrier-grade or symmetric/hostile, where direct inbound
/// reachability is not expected and no port mapping can be relied on.</summary>
public enum NatClass
{
    Unknown,          // no usable address facts at all
    PublicDirect,     // a public address sits on a local interface: no NAT in the way here
    BehindNat,        // private interface address: at least one NAT upstream; depth unobservable locally
    CarrierGradeNat,  // CGNAT (100.64.0.0/10) that is NOT the tailnet — the ISP's NAT
    DoubleNat,        // local private address AND the WAN-side address is also private/CGNAT
    Hostile           // explicitly reported symmetric/hostile NAT (e.g. by a peer that could observe it)
}

public enum RungState
{
    Reachable,     // positive evidence only (bound lane / recorded success)
    Configured,    // set up, never yet carried traffic, no failure recorded
    Dormant,       // registered, not configured for use
    Failed,        // a recorded attempt failed — reason attached
    NotConfigured, // known rung, missing its configuration
    NotRegistered  // named in policy, no implementation in this build
}

/// <summary>One failure (or caution) as the owner reads it:
/// what happened, why in plain language, and the fix step.</summary>
public sealed record DoctorFinding(string What, string Why, string Fix);

/// <summary>One rung's honest line in the report.</summary>
public sealed record RungReport(
    string Rung, RungState State, string Evidence,
    DoctorFinding? Finding, bool IsD18Corner);

/// <summary>Immutable snapshot of one rung, taken by the caller from
/// state it already owns (engine events, lane status, config
/// presence). The doctor never reaches into a live rung.</summary>
public sealed record RungSnapshot(
    string Id,
    bool Registered,
    bool Configured,
    int ConnectAttempts,
    string? LastAttemptDetail = null,
    bool LastAttemptSucceeded = false,
    bool LaneBound = false,
    string? LanePhaseName = null,
    string? LaneAddress = null);

/// <summary>Everything the doctor is allowed to look at. All facts
/// are pre-collected by the caller from the product's own state;
/// <paramref name="PeerAddress"/>/<paramref name="PeerNat"/> describe
/// a peer the caller already knows (enrolled/discovered) and are
/// classified, never contacted. <paramref name="WanAddress"/> is the
/// WAN-side address if the owner/router already reports one locally
/// (else null — double-NAT then stays honestly unobservable).</summary>
public sealed record DoctorFacts(
    IReadOnlyList<string> LocalAddresses,
    IReadOnlyList<RungSnapshot> Rungs,
    string? PeerAddress = null,
    NatClass PeerNat = NatClass.Unknown,
    string? WanAddress = null,
    bool HasUserOwnedRelay = false,
    IReadOnlyCollection<string>? TailnetAddresses = null);

public sealed record DoctorReport(
    NatClass LocalNat,
    AddressClass LocalAddressClass,
    NatClass PeerNat,
    bool IsD18Corner,
    string NatNote,
    IReadOnlyList<RungReport> Rungs,
    IReadOnlyList<DoctorFinding> Findings,
    string Summary,
    NatClass LocalNatV6 = NatClass.Unknown);

public static class ConnectionDoctor
{
    public const string D18Name = "D18";
    public const string D18Explanation =
        "This is the D18 exception: both ends sit behind hostile NATs (carrier-grade or symmetric) " +
        "and no user-owned node exists to relay. DeskGuest does not guarantee a relay in this corner — " +
        "it is one of the five named D18 exceptions, not a bug and not a setting you missed.";

    // ---------- address classification (parse-only, no traffic) ----------

    public static AddressClass ClassifyAddress(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return AddressClass.NotAnAddress;
        var host = text.Trim();
        // Accept host:port and [v6]:port shapes the product already stores.
        if (host.StartsWith("[") && host.Contains(']')) host = host[1..host.IndexOf(']')];
        else if (host.Count(c => c == ':') == 1) host = host[..host.IndexOf(':')];
        if (!IPAddress.TryParse(host, out var ip)) return AddressClass.NotAnAddress;
        if (IPAddress.IsLoopback(ip)) return AddressClass.Loopback;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return AddressClass.LinkLocal;
            if ((b[0] & 0xFE) == 0xFC) return AddressClass.Ipv6PrivateOrLocal;
            if ((b[0] & 0xE0) == 0x20) return AddressClass.Ipv6Global;
            return AddressClass.Ipv6Other;
        }
        if (b[0] == 169 && b[1] == 254) return AddressClass.LinkLocal;
        // BD-SHARED-SESSION F9: special-purpose ranges are Reserved,
        // never Public.
        if (b[0] == 0) return AddressClass.Reserved;                                   // 0.0.0.0/8
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return AddressClass.Reserved;       // TEST-NET-1
        if (b[0] == 198 && (b[1] & 0xFE) == 18) return AddressClass.Reserved;          // 198.18.0.0/15
        if (b[0] >= 224) return AddressClass.Reserved;                                 // multicast + reserved
        if (b[0] == 100 && (b[1] & 0xC0) == 0x40) return AddressClass.CarrierGradeNat;
        if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168))
            return AddressClass.PrivateRfc1918;
        return AddressClass.Public;
    }

    /// <summary>The tailnet also lives in 100.64.0.0/10 — a tailnet
    /// address is DeskGuest's own lane, not the ISP's CGNAT. Callers pass
    /// the addresses their lane probe already identified as tailnet.</summary>
    /// <summary>BD-SHARED-SESSION F9: is this address in the tailnet
    /// CGNAT range AND shaped like the tailnet's own allocation?
    /// Tailscale assigns 100.64.0.0/10 — indistinguishable from ISP
    /// CGNAT by range alone, which is exactly why callers pass the
    /// lane probe's set. When NO set is supplied, this helper is the
    /// documented fallback used for PEER classification only: a peer
    /// address in 100/10 that the caller knows from enrollment is
    /// still reported CGNAT (hostile-safe), never Public.</summary>
    private static bool IsTailnetAddress(string a, IReadOnlyCollection<string>? tailnet) =>
        tailnet is not null && tailnet.Contains(a);

    public static NatClass ClassifyNat(IReadOnlyList<string> localAddresses, string? wanAddress = null,
        IReadOnlyCollection<string>? tailnetAddresses = null)
    {
        // BD-SHARED-SESSION F9: IPv4 and IPv6 are classified
        // SEPARATELY — a global IPv6 address no longer makes the
        // IPv4 situation "PublicDirect" (that suppressed D18 for
        // IPv4-behind-NAT devices). ClassifyNat remains the IPv4
        // verdict for compatibility; ClassifyNatV6 is the v6 one,
        // and Diagnose reports both.
        var v4 = localAddresses.Where(a => !(a.Contains(':') && !a.StartsWith("[")) || a.Count(c => c == ':') == 1)
            .ToList();
        var classes = v4.Select(a =>
            IsTailnetAddress(a, tailnetAddresses)
                ? AddressClass.TailnetCgnat : ClassifyAddress(a))
            .Where(c => c is not (AddressClass.NotAnAddress or AddressClass.Loopback or AddressClass.LinkLocal
                or AddressClass.Reserved or AddressClass.Ipv6Global or AddressClass.Ipv6PrivateOrLocal
                or AddressClass.Ipv6Other))
            .ToList();
        if (classes.Count == 0)
        {
            // No IPv4 facts: fall back to the v6 verdict so a v6-only
            // device still classifies (honest: it IS its only family).
            var v6 = ClassifyNatV6(localAddresses);
            return v6 == NatClass.PublicDirect ? NatClass.PublicDirect : NatClass.Unknown;
        }
        if (classes.Contains(AddressClass.Public))
            return NatClass.PublicDirect;
        if (classes.Contains(AddressClass.CarrierGradeNat)) return NatClass.CarrierGradeNat;
        // Private local address: is the WAN side ALSO private/CGNAT?
        // Only then can double NAT be claimed — and only when a WAN
        // address was actually supplied from local facts.
        var wan = wanAddress is null ? AddressClass.NotAnAddress : ClassifyAddress(wanAddress);
        if (wan is AddressClass.PrivateRfc1918 or AddressClass.CarrierGradeNat) return NatClass.DoubleNat;
        return NatClass.BehindNat;
    }

    /// <summary>BD-SHARED-SESSION F9: the IPv6 NAT verdict, kept
    /// separate from IPv4. Global v6 = direct; ULA/link-local only =
    /// behind whatever v6 NAT/ firewalling exists (reported
    /// BehindNat, honestly — v6 NAT depth is equally unobservable).</summary>
    public static NatClass ClassifyNatV6(IReadOnlyList<string> localAddresses)
    {
        var classes = localAddresses.Select(ClassifyAddress)
            .Where(c => c is AddressClass.Ipv6Global or AddressClass.Ipv6PrivateOrLocal or AddressClass.Ipv6Other)
            .ToList();
        if (classes.Count == 0) return NatClass.Unknown;
        if (classes.Contains(AddressClass.Ipv6Global)) return NatClass.PublicDirect;
        return NatClass.BehindNat;
    }

    /// <summary>BD-SHARED-SESSION F9: local interface addresses WITH
    /// the tailnet set derived from the interfaces themselves (the
    /// Tailscale interface's own addresses, by interface name/
    /// description) — callers no longer have to thread a possibly-
    /// null tailnet list for the doctor to avoid calling the
    /// tailnet ISP CGNAT.</summary>
    public static (IReadOnlyList<string> Addresses, IReadOnlyList<string> TailnetAddresses) LocalInterfaceAddressesTagged()
    {
        var addrs = new List<string>(); var tailnet = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var isTailnet = (ni.Name + " " + ni.Description)
                    .Contains("tailscale", StringComparison.OrdinalIgnoreCase) ||
                    (ni.Name + " " + ni.Description)
                    .Contains("wintun", StringComparison.OrdinalIgnoreCase);
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    addrs.Add(ua.Address.ToString());
                    if (isTailnet) tailnet.Add(ua.Address.ToString());
                }
            }
        }
        catch { /* unreadable interfaces = no facts, honestly */ }
        return (addrs, tailnet);
    }

    public static bool IsHostileNat(NatClass nat) => nat is NatClass.CarrierGradeNat or NatClass.Hostile;

    /// <summary>D18 corner: BOTH ends hostile, no user-owned relay,
    /// and no rung with positive reachability evidence.</summary>
    public static bool IsD18Corner(NatClass local, NatClass peer, bool hasUserOwnedRelay, bool anyRungReachable) =>
        IsHostileNat(local) && IsHostileNat(peer) && !hasUserOwnedRelay && !anyRungReachable;

    // ---------- the report ----------

    public static DoctorReport Diagnose(DoctorFacts facts)
    {
        var localClass = facts.LocalAddresses
            .Select(ClassifyAddress)
            .FirstOrDefault(c => c is not (AddressClass.NotAnAddress or AddressClass.Loopback),
                AddressClass.NotAnAddress);
        var localNat = ClassifyNat(facts.LocalAddresses, facts.WanAddress, facts.TailnetAddresses);
        var localNatV6 = ClassifyNatV6(facts.LocalAddresses);
        var peerNat = facts.PeerNat;
        if (peerNat == NatClass.Unknown && facts.PeerAddress is not null)
            // BD-SHARED-SESSION F9: the tailnet set applies to the
            // PEER too — a peer reached over our own tailnet is not
            // an ISP-CGNAT stranger.
            peerNat = facts.TailnetAddresses is not null && facts.TailnetAddresses.Contains(facts.PeerAddress)
                ? NatClass.BehindNat
                : ClassifyAddress(facts.PeerAddress) switch
                {
                    AddressClass.CarrierGradeNat => NatClass.CarrierGradeNat,
                    AddressClass.PrivateRfc1918 => NatClass.BehindNat,
                    AddressClass.Public or AddressClass.Ipv6Global => NatClass.PublicDirect,
                    _ => NatClass.Unknown
                };

        var anyReachable = facts.Rungs.Any(HasPositiveEvidence);
        var d18 = IsD18Corner(localNat, peerNat, facts.HasUserOwnedRelay, anyReachable);

        var rungs = facts.Rungs.Select(r => ReportRung(r, d18)).ToList();
        var findings = rungs.Where(r => r.Finding is not null).Select(r => r.Finding!).ToList();

        var natNote = NatNote(localNat);
        if (d18) findings.Insert(0, new DoctorFinding(
            "No path can be guaranteed between these two devices",
            D18Explanation,
            "Put one end on a reachable network (public address, or a network whose NAT allows inbound mappings), " +
            "or add a user-owned node (for example your own hub) that both ends can reach, then run the doctor again."));

        var summary = d18
            ? $"Connection doctor: D18 corner — both ends are behind hostile NATs and no rung has a proven path. {rungs.Count(r => r.State == RungState.Reachable)} of {rungs.Count} rung(s) proven reachable."
            : anyReachable
                ? $"Connection doctor: at least one rung is proven reachable. {findings.Count} thing(s) still need attention."
                : $"Connection doctor: no rung is proven reachable yet. {findings.Count} finding(s) below say why, in plain language, with the fix for each.";

        return new DoctorReport(localNat, localClass, peerNat, d18, natNote, rungs, findings, summary, localNatV6);
    }

    private static bool HasPositiveEvidence(RungSnapshot r) =>
        r.LaneBound || (r.ConnectAttempts > 0 && r.LastAttemptSucceeded);

    private static RungReport ReportRung(RungSnapshot r, bool d18)
    {
        if (!r.Registered)
            return new(r.Id, RungState.NotRegistered, "named in the transport set but no implementation is registered in this build",
                new DoctorFinding($"The '{r.Id}' path is listed but not available",
                    "This build does not contain that transport, so the connection engine skips it every time.",
                    $"Remove '{r.Id}' from the transport set, or use a build that includes it."), false);

        if (HasPositiveEvidence(r))
            return new(r.Id, RungState.Reachable,
                r.LaneBound ? $"listener bound on {r.LaneAddress ?? "its lane address"}"
                            : $"last attempt succeeded: {r.LastAttemptDetail ?? "connected"}",
                null, false);

        if (r.ConnectAttempts > 0)
        {
            // A recorded failure is evidence of failure — never of health.
            var why = PlainReason(r);
            return new(r.Id, RungState.Failed,
                $"attempted {r.ConnectAttempts} time(s); last result: {r.LastAttemptDetail ?? "failed"}",
                new DoctorFinding($"The '{r.Id}' path was tried and did not connect", why,
                    FixFor(r, d18)), d18);
        }

        if (!r.Configured)
            return new(r.Id, RungState.NotConfigured, "registered but its configuration is missing",
                new DoctorFinding($"The '{r.Id}' path is not set up",
                    "DeskGuest knows this transport but the information it needs (an address, a peer, or a setup step) is not in place, so it cannot be tried.",
                    $"Complete the '{r.Id}' setup step, then run the doctor again."), false);

        // Configured but never tried and no lane bound: dormant.
        // Honest wording: this is NOT reachable and NOT failed.
        return new(r.Id, r.LanePhaseName is null ? RungState.Configured : RungState.Dormant,
            r.LanePhaseName is null ? "configured; never attempted yet — reachability is unproven, not confirmed"
                                    : $"lane phase {r.LanePhaseName}; never attempted — reachability is unproven, not confirmed",
            new DoctorFinding($"The '{r.Id}' path has not been tried yet",
                "Nothing has attempted this path, so the doctor cannot call it working. A path that was never tried is not a healthy path.",
                "Start a connection so this path is attempted, then run the doctor again to see the recorded result."), false);
    }

    private static string PlainReason(RungSnapshot r)
    {
        var d = (r.LastAttemptDetail ?? "").ToLowerInvariant();
        if (d.Contains("no address")) return "There is no address to connect to: the device was not discovered and no address was entered by hand.";
        if (d.Contains("refused our proof") || d.Contains("refused")) return "The other device answered but refused this device's proof of identity — the pairing/enrollment does not match, or it was revoked.";
        if (d.Contains("no deskguest challenge") || d.Contains("did not speak")) return "Something answered at that address, but it was not DeskGuest — the address or port points at a different service.";
        if (d.Contains("no global ipv6")) return "This device has no global IPv6 address, so the IPv6 path cannot start from here.";
        if (d.Contains("not") && d.Contains("ipv6")) return "The other device's address is not a globally reachable IPv6 address.";
        if (r.LanePhaseName is "NoAddress") return "This device has no address on that network right now (for the tailnet path: Tailscale is not up on this device).";
        if (r.LanePhaseName is "BindFailed") return "The address exists but DeskGuest could not listen on it — something else may already be using it, or the address changed mid-start.";
        return $"The attempt failed ({r.LastAttemptDetail ?? "no detail recorded"}). The recorded result is quoted in the evidence line; no more specific cause was observed.";
    }

    private static string FixFor(RungSnapshot r, bool d18)
    {
        if (d18) return "See the D18 finding at the top: this failure is the both-ends-hostile-NAT corner.";
        var d = (r.LastAttemptDetail ?? "").ToLowerInvariant();
        if (d.Contains("no address")) return "Run discovery on the same network, or enter the device's address by hand (connect-by-address), then try again.";
        if (d.Contains("refused")) return "Re-check the pairing on both devices; if the pairing was revoked, pair again from scratch.";
        if (d.Contains("did not speak") || d.Contains("no deskguest challenge")) return "Check the address and port point at the DeskGuest device you meant, not another service.";
        if (r.LanePhaseName is "NoAddress") return "Bring that network up on this device (start Tailscale / join the LAN), then run the doctor again.";
        if (r.LanePhaseName is "BindFailed") return "Check nothing else is listening on DeskGuest's port, then restart DeskGuest so the listener retries.";
        return "Check both devices are on, DeskGuest is running on the other device, and the address is current; then try the connection again.";
    }

    private static string NatNote(NatClass nat) => nat switch
    {
        NatClass.PublicDirect => "This device has a public address on its own network interface, so no NAT sits in front of it here.",
        NatClass.BehindNat => "This device sits behind at least one NAT (its own address is private). How many NATs are stacked upstream cannot be seen from this device alone — the doctor does not send STUN or any other outside probe, so it will not guess.",
        NatClass.CarrierGradeNat => "This device's address is in the carrier-grade NAT range (100.64.0.0/10) and is not the tailnet: the internet provider is NAT-ing this connection. Inbound connections from the public internet are not expected to arrive.",
        NatClass.DoubleNat => "Double NAT: this device's address is private AND the WAN-side address reported locally is also private/carrier-grade. Two NAT layers must both allow a path for a direct inbound connection.",
        NatClass.Hostile => "This connection's NAT has been reported as symmetric/hostile: port mappings do not stay predictable, so direct paths usually fail.",
        _ => "No usable network address was found on this device, so its NAT situation cannot be classified."
    };

    /// <summary>Local interface addresses from the OS — enumeration
    /// only, the same facts NetworkProbe already reads. No traffic.</summary>
    public static IReadOnlyList<string> LocalInterfaceAddresses()
    {
        var outp = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    outp.Add(ua.Address.ToString());
            }
        }
        catch { /* unreadable interfaces = no facts, honestly */ }
        return outp;
    }
}
