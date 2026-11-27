using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.NetworkDiscovery;

// =====================================================================
// RMM-11 — Network discovery + agentless monitoring (ADOPTED
// 2026-11-20). MODEL LAYER (this file): the probe scope, probe
// observations, the site census with drift + poisoning discipline,
// and the topology model (nodes/edges as DATA — rendering is the
// design phase, not this lane). The monitoring parsers (SNMP /
// syslog / flow / config backup) live in NetworkMonitoring.cs; the
// orchestrating probe service lives in DeskGuest.Core
// (NetworkDiscoveryService), following the Wake-on-LAN sibling
// shape: the probe runs on an DeskGuest device that already sits on the
// site LAN, requests reach it over DeskGuest transports, and discovery
// data NEVER leaves the site (no outbound anything in this layer —
// every transport is an injected interface; tests drive fakes and
// no code here opens a socket).
//
// Politeness + scope law (register text): probing is BOUNDED —
// the scope is the site's subnets as configured by policy, sweeps
// are rate-limited and host-capped, and an observation that
// answers from OUTSIDE the configured scope is refused, never
// filed (scope escape is an attack, not a discovery).
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-11. The feature
/// toggles themselves are seeded in the RMM-07 registry
/// (`rmm.network_discovery.enabled` default ON;
/// `rmm.camera_viewing.enabled` default OFF — see CameraViewing.cs);
/// the settings keys below carry the probe's scope + rate content
/// through the same Effective Policy machinery.</summary>
public static class NetworkDiscoveryPolicyKeys
{
    public const string DiscoveryEnabled = "rmm.network_discovery.enabled";
    /// <summary>Comma-separated CIDRs naming the site's subnets.
    /// Set at org/group/device level for the probe's facts; the
    /// service's constructor scope is only the fallback when policy
    /// sets nothing.</summary>
    public const string Subnets = "rmm.network_discovery.subnets";
    public const string MaxHostsPerSweep = "rmm.network_discovery.max_hosts_per_sweep";
    public const string MinSweepIntervalSeconds = "rmm.network_discovery.min_sweep_interval_seconds";
}

/// <summary>Alert kinds RMM-11 raises into RMM-01's alert centre
/// (HealthAlertCentre — the same centre, the same hash-chained
/// audit; there is no second alert surface). Rogue-device and
/// identity-drift flags are CONDITIONS-shaped: a condition id per
/// subject, deduped by the centre like every other alert.</summary>
public static class NetworkAlertKinds
{
    public const string RogueDevice = "rogue_device";
    public const string IdentityDrift = "identity_drift";
    public const string ConfigChanged = "config_changed";
    public const string SnmpThreshold = "snmp_threshold";
    public const string SnmpTrap = "snmp_trap";
    public const string SyslogKeyword = "syslog_keyword";
}

/// <summary>IP / CIDR helpers — the scope arithmetic of the probe.
/// Pure; every refusal is a value, never an exception.</summary>
public static class NetworkAddressing
{
    /// <summary>An address the probe may target / file: a unicast
    /// host address. Loopback, link-local (incl. the 169.254.169.254
    /// cloud-metadata address), multicast, unspecified and broadcast
    /// are NEVER discovery targets — the same SSRF-shaped line the
    /// RMM-04 register draws at registration, drawn here at probe
    /// time as an independent second line.</summary>
    /// <summary>FIX (D38 F1): an IPv4-mapped IPv6 address
    /// (::ffff:a.b.c.d) IS the IPv4 address for every scope and
    /// probeability decision — without unwrapping, the mapped form
    /// of the metadata/loopback/link-local addresses slipped past
    /// the v4 checks below, which only ran for the InterNetwork
    /// family. Every entry point in this file unwraps first.</summary>
    public static IPAddress UnwrapMapped(IPAddress ip) =>
        ip is not null && ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    public static bool IsProbeableHost(IPAddress ip)
    {
        ip = UnwrapMapped(ip);
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
            ip.Equals(IPAddress.Broadcast)) return false;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (bytes[0] == 169 && bytes[1] == 254) return false; // link-local + metadata
            if (bytes[0] >= 224) return false;                    // multicast / reserved
            if (bytes[0] == 0) return false;                      // "this host" block
            if (bytes[0] == 127) return false;                    // loopback block (belt: IsLoopback covers it)
        }
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal)) return false;
        return true;
    }

    public static bool TryParseCidr(string? cidr, out IPAddress network, out int prefixLength)
    {
        network = IPAddress.None; prefixLength = -1;
        if (string.IsNullOrWhiteSpace(cidr)) return false;
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out var ip)) return false;
        if (!int.TryParse(parts[1], out var prefix)) return false;
        // FIX (D38 F1): a mapped-v6 CIDR ("::ffff:169.254.0.0/112")
        // names the v4 network — unwrap and shift the prefix into
        // v4 terms so scope arithmetic compares like with like.
        if (ip.IsIPv4MappedToIPv6)
        {
            if (prefix < 96) return false;
            prefix -= 96;
            ip = ip.MapToIPv4();
        }
        var max = ip.GetAddressBytes().Length * 8;
        if (prefix < 0 || prefix > max) return false;
        // The address must BE the network address (host bits zero) —
        // "10.0.0.5/24" as a scope is an admin error, refused loudly
        // here rather than silently widened to the /24 anyway.
        var bytes = ip.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = prefix - i * 8;
            var mask = bits >= 8 ? (byte)0xFF : bits <= 0 ? (byte)0x00 : (byte)(0xFF << (8 - bits));
            if ((bytes[i] & ~mask) != 0) return false;
        }
        network = ip; prefixLength = prefix;
        return true;
    }

    public static bool IsInCidr(IPAddress ip, IPAddress network, int prefixLength)
    {
        var a = UnwrapMapped(ip).GetAddressBytes();
        var b = UnwrapMapped(network).GetAddressBytes();
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
        {
            var bits = prefixLength - i * 8;
            var mask = bits >= 8 ? (byte)0xFF : bits <= 0 ? (byte)0x00 : (byte)(0xFF << (8 - bits));
            if ((a[i] & mask) != (b[i] & mask)) return false;
        }
        return true;
    }

    /// <summary>Enumerate the host addresses of a CIDR, capped.
    /// Network + broadcast addresses are skipped for prefixes
    /// ≤ /30 (v4) — they are not hosts. The cap is a hard stop:
    /// enumeration yields at most `cap` addresses, in order.</summary>
    public static IEnumerable<IPAddress> EnumerateHosts(IPAddress network, int prefixLength, int cap)
    {
        var bytes = UnwrapMapped(network).GetAddressBytes();
        var isV4 = bytes.Length == 4;
        // FIX (D38 F2b): the host count is 2^(address width −
        // prefix) for BOTH families — the old "prefix ≥ 64 ⇒
        // unbounded" shortcut let a v6 /120 or /128 enumerate PAST
        // its subnet up to the cap, probing out-of-scope addresses.
        var hostBits = bytes.Length * 8 - prefixLength;
        long total = hostBits >= 63 ? long.MaxValue : 1L << hostBits;
        long start = 0, end = total;
        if (isV4 && prefixLength <= 30 && total >= 4) { start = 1; end = total - 1; }
        var yielded = 0;
        for (var offset = start; offset < end && yielded < cap; offset++)
        {
            var addr = (byte[])bytes.Clone();
            var remaining = offset;
            for (var i = addr.Length - 1; i >= 0 && remaining > 0; i--)
            {
                var sum = addr[i] + (remaining & 0xFF);
                addr[i] = (byte)(sum & 0xFF);
                remaining = (remaining >> 8) + (sum >> 8);
            }
            yielded++;
            yield return new IPAddress(addr);
        }
    }
}

/// <summary>The probe's configured scope: the site's subnets (from
/// policy), the per-sweep host cap and the minimum sweep interval.
/// A scope that fails Validate() authorizes NOTHING — the service
/// refuses to sweep rather than guess a scope.</summary>
public sealed record ProbeScope(
    string ScopeId,
    IReadOnlyList<string> Subnets,
    int MaxHostsPerSweep,
    TimeSpan MinSweepInterval)
{
    public const int DefaultMaxHostsPerSweep = 1024;
    public const int HardMaxHostsPerSweep = 4096;
    public static readonly TimeSpan DefaultMinSweepInterval = TimeSpan.FromMinutes(5);

    public IReadOnlyList<string> Subnets { get; init; } = Subnets ?? Array.Empty<string>();

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(ScopeId)) return "probe scope needs a scope id — refused";
        if (Subnets.Count == 0) return "probe scope names no subnets — refused (an unbounded scan is never authorized)";
        if (Subnets.Count > 32) return "probe scope names more than 32 subnets — refused";
        foreach (var s in Subnets)
        {
            if (!NetworkAddressing.TryParseCidr(s, out var net, out _))
                return $"probe scope subnet '{s}' is not a network CIDR — refused";
            // FIX (D38 F2a): a scope naming loopback, link-local /
            // metadata, multicast, unspecified or site-local space
            // authorizes probes at non-probeable targets (the SSRF
            // shape). The network address of such a CIDR is itself
            // non-probeable, so the scope is refused here — before
            // any probe can be sent — not discovered at filing time.
            if (!NetworkAddressing.IsProbeableHost(net))
                return $"probe scope subnet '{s}' names non-probeable address space (loopback/link-local/multicast/unspecified) — refused";
        }
        if (MaxHostsPerSweep <= 0 || MaxHostsPerSweep > HardMaxHostsPerSweep)
            return $"max hosts per sweep must be within 1..{HardMaxHostsPerSweep} — refused";
        if (MinSweepInterval < TimeSpan.Zero) return "minimum sweep interval cannot be negative — refused";
        return null;
    }

    public bool Contains(IPAddress ip)
    {
        foreach (var s in Subnets)
            if (NetworkAddressing.TryParseCidr(s, out var net, out var prefix) &&
                NetworkAddressing.IsInCidr(ip, net, prefix))
                return true;
        return false;
    }

    public static ProbeScope Default(string scopeId, params string[] subnets) =>
        new(scopeId, subnets, DefaultMaxHostsPerSweep, DefaultMinSweepInterval);
}

// ---- observations --------------------------------------------------------

/// <summary>The SNMP profile of a discovered device, from a
/// credentialess/community or credentialed SNMP read: the system
/// group facts a profiler can state honestly. Null fields are
/// facts not read, never guesses.</summary>
public sealed record SnmpProfile(
    string? SysDescr,
    string? SysName,
    string? SysObjectId,
    string? SysContact,
    string? SysLocation);

/// <summary>One probe observation: what ONE host answered during a
/// sweep — credentialess TCP (open ports), SNMP profiling, SSH
/// banner, HTTP server header, ONVIF presence. This is the raw
/// evidence; the census (below) is what the sweep makes of it.</summary>
public sealed record ProbeObservation(
    string IpAddress,
    string? MacAddress,
    string? Hostname,
    IReadOnlyList<int> OpenPorts,
    SnmpProfile? Snmp,
    string? SshBanner,
    string? HttpServer,
    bool OnvifCapable,
    DateTimeOffset ObservedUtc,
    // BD-SHARED-TRANSPORT F7: an answering RTSP service is
    // RTSP-capable evidence — it was previously filed as
    // OnvifCapable, claiming an ONVIF conformance the probe
    // never tested. The two flags are separate now.
    bool RtspCapable = false)
{
    public IReadOnlyList<int> OpenPorts { get; init; } = OpenPorts ?? Array.Empty<int>();
}

/// <summary>The probe's exit door (the Wake IWakeSender shape): one
/// host probe per call. The production implementation performs the
/// bounded TCP connect sweep + SNMP/SSH profiling on the site LAN;
/// it is hub/probe-host wiring and deliberately not in this model
/// layer. Tests substitute the recorder below — NO test touches a
/// real network.</summary>
public interface IProbeTransport
{
    /// <summary>Probe one host. Null = no answer (nothing filed).
    /// An observation whose IpAddress differs from the probed
    /// address is a scope-escape witness: the service refuses it.</summary>
    ProbeObservation? Probe(string ipAddress, DateTimeOffset now);
}

/// <summary>Recording fake (house pattern: fakes live beside the
/// model). Scripted per-IP answers; unscripted IPs do not answer.</summary>
public sealed class FakeProbeTransport : IProbeTransport
{
    private readonly Dictionary<string, ProbeObservation?> _script = new(StringComparer.OrdinalIgnoreCase);
    public List<string> ProbedIps { get; } = new();
    public Func<string, DateTimeOffset, ProbeObservation?>? Handler { get; set; }

    public FakeProbeTransport Script(string ip, ProbeObservation? observation)
    {
        _script[ip] = observation;
        return this;
    }

    public ProbeObservation? Probe(string ipAddress, DateTimeOffset now)
    {
        ProbedIps.Add(ipAddress);
        if (Handler is not null) return Handler(ipAddress, now);
        return _script.TryGetValue(ipAddress, out var obs) ? obs : null;
    }
}

// ---- fingerprints + kind guessing -----------------------------------------

public static class DeviceFingerprint
{
    /// <summary>The identity fingerprint: MAC + SNMP object id +
    /// the sorted open-port set + the SSH banner, hashed. Hostname
    /// is deliberately EXCLUDED — a DHCP rename is not an identity
    /// change; a MAC, object-id, port-surface or banner change IS
    /// drift and is named as such by the census.</summary>
    public static string Compute(ProbeObservation obs)
    {
        var mac = NormalizeMac(obs.MacAddress) ?? "";
        var ports = string.Join(",", (obs.OpenPorts ?? Array.Empty<int>()).Distinct().OrderBy(p => p));
        var material = string.Join("|", mac,
            (obs.Snmp?.SysObjectId ?? "").Trim(),
            ports,
            (obs.SshBanner ?? "").Trim());
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    public static string? NormalizeMac(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var hex = new string(raw.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12) return null;
        hex = hex.ToUpperInvariant();
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    /// <summary>Deterministic kind guess from ports + SNMP facts.
    /// Returns an UnmanagedAssetKinds slug or "other". A guess is a
    /// filing hint for the admin, never an identity claim.</summary>
    public static string GuessKind(ProbeObservation obs)
    {
        var ports = new HashSet<int>(obs.OpenPorts ?? Array.Empty<int>());
        var descr = ((obs.Snmp?.SysDescr ?? "") + " " + (obs.Snmp?.SysObjectId ?? "")).ToLowerInvariant();
        if (obs.OnvifCapable || ports.Contains(554) || descr.Contains("camera") ||
            descr.Split(' ', ',', ';').Any(t => t == "cam")) return "camera";
        if (descr.Contains("printer") || ports.Contains(9100) || ports.Contains(515) || ports.Contains(631))
            return "printer";
        if (descr.Contains("ups") || descr.Contains("apc ") || ports.Contains(3493)) return "ups";
        if (descr.Contains("niagara") || descr.Contains("jace") || descr.Contains("tridium") ||
            descr.Contains("bacnet") || ports.Contains(47808)) return "bas-controller";
        if (descr.Contains("switch") || descr.Contains("catalyst") || descr.Contains("procurve"))
            return "network-switch";
        if (ports.Contains(5060) || ports.Contains(5061)) return "phone";
        if (ports.Contains(161) && (descr.Contains("wireless") || descr.Contains("access point"))) return "access-point";
        if (ports.Contains(22) || ports.Contains(23)) return "network-switch"; // managed network gear until profiled further
        return "other";
    }
}

// ---- the census ------------------------------------------------------------

public static class CensusDriftKinds
{
    public const string IpChanged = "ip_changed";               // same MAC, new IP (DHCP move — recorded, low severity)
    public const string MacChanged = "mac_changed";             // same IP, new MAC (device swapped or spoofed)
    public const string FingerprintChanged = "fingerprint_changed"; // same MAC+IP, new identity surface
    public const string MacClaimedManyIps = "mac_claimed_many_ips"; // poisoning: one MAC, many IPs in one sweep
    public const string IpClaimedByManyMacs = "ip_claimed_by_many_macs";
}

public sealed record CensusEntry(
    string EntryId,            // normalized MAC when known, else "ip:<address>"
    string IpAddress,
    string? MacAddress,
    string Fingerprint,
    string KindGuess,
    string? Make,
    string? Model,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int SweepCount,
    bool Quarantined,
    IReadOnlyList<string> DriftFlags)
{
    public IReadOnlyList<string> DriftFlags { get; init; } = DriftFlags ?? Array.Empty<string>();
}

public sealed record CensusUpsertResult(
    string Outcome,            // "added" | "updated" | "drift" | "quarantined" | "refused"
    CensusEntry? Entry,
    IReadOnlyList<string> DriftKinds,
    string Detail)
{
    public const string Added = "added";
    public const string Updated = "updated";
    public const string Drift = "drift";
    public const string Quarantined = "quarantined";
    public const string Refused = "refused";
}

/// <summary>The site census: every device the probe has seen,
/// keyed by identity (MAC when known). The census is the drift
/// baseline — rogue detection compares it against the register +
/// the managed fleet; drift is judged against its own history.
///
/// Poisoning discipline: within ONE sweep, a single MAC claiming
/// more than MaxIpsPerMacPerSweep addresses, or a single IP
/// claimed by two MACs, quarantines the identity — its entries are
/// kept (evidence) but flagged, and the discovery service does not
/// land quarantined entries in the register. One hostile device
/// therefore cannot mint a crowd of trusted census identities.</summary>
public sealed class SiteCensus
{
    public const int MaxEntries = 4096;
    public const int MaxIpsPerMacPerSweep = 4;
    /// <summary>FIX (D38 F7): when the census is full, an entry not
    /// seen for this long is stale evidence (a departed phone with
    /// a randomized MAC, a decommissioned box) and is evicted to
    /// make room for a live identity — the census no longer grows
    /// to the cap and then silently stops reporting new devices.
    /// Entries younger than this are NEVER evicted: a full census
    /// of fresh entries still refuses (DG-R11-14).</summary>
    public static readonly TimeSpan StaleEvictionAge = TimeSpan.FromDays(30);

    private readonly Dictionary<string, CensusEntry> _byId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _entryIdByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    // Per-sweep poisoning witnesses, reset when the sweep id changes.
    private string? _sweepId;
    private readonly Dictionary<string, HashSet<string>> _sweepMacIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _sweepIpMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sweepQuarantinedMacs = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<CensusEntry> Entries
    {
        get { lock (_gate) return _byId.Values.OrderBy(e => e.EntryId, StringComparer.Ordinal).ToList(); }
    }

    public CensusEntry? Get(string entryId)
    {
        lock (_gate) return entryId is not null && _byId.TryGetValue(entryId, out var e) ? e : null;
    }

    public CensusEntry? FindByIp(string ip)
    {
        lock (_gate)
            return ip is not null && _entryIdByIp.TryGetValue(ip, out var id) &&
                   _byId.TryGetValue(id, out var e) ? e : null;
    }

    public CensusEntry? FindByMac(string mac)
    {
        var normalized = DeviceFingerprint.NormalizeMac(mac);
        lock (_gate) return normalized is not null && _byId.TryGetValue(normalized, out var e) ? e : null;
    }

    public CensusUpsertResult Upsert(ProbeObservation obs, string sweepId, DateTimeOffset now)
    {
        if (obs is null || !IPAddress.TryParse(obs.IpAddress ?? "", out var ip) ||
            !NetworkAddressing.IsProbeableHost(ip))
            return new CensusUpsertResult(CensusUpsertResult.Refused, null,
                Array.Empty<string>(), "observation carries no probeable host address — refused");
        // FIX (D38 F1): file the identity under its unwrapped form —
        // "::ffff:10.0.0.1" and "10.0.0.1" are ONE device, one entry.
        ip = NetworkAddressing.UnwrapMapped(ip);
        var ipText = ip.ToString();
        var mac = DeviceFingerprint.NormalizeMac(obs.MacAddress);
        var fingerprint = DeviceFingerprint.Compute(obs);
        lock (_gate)
        {
            if (!string.Equals(_sweepId, sweepId, StringComparison.Ordinal))
            {
                _sweepId = sweepId;
                _sweepMacIps.Clear(); _sweepIpMacs.Clear(); _sweepQuarantinedMacs.Clear();
            }
            // --- poisoning witnesses (this sweep) ---
            var poisoned = false;
            if (mac is not null)
            {
                if (!_sweepMacIps.TryGetValue(mac, out var ips)) _sweepMacIps[mac] = ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ips.Add(ipText);
                if (!_sweepIpMacs.TryGetValue(ipText, out var macs)) _sweepIpMacs[ipText] = macs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                macs.Add(mac);
                if (ips.Count > MaxIpsPerMacPerSweep || macs.Count > 1)
                {
                    poisoned = true;
                    _sweepQuarantinedMacs.Add(mac);
                    // FIX (D38 F3c): when one IP is claimed by two
                    // MACs, BOTH claimants quarantine — the old code
                    // flagged only the second claimant, so the first
                    // (the spoofer, in the ARP-spoof shape) landed
                    // clean while the victim took the flag.
                    if (macs.Count > 1)
                        foreach (var claimant in macs)
                        {
                            _sweepQuarantinedMacs.Add(claimant);
                            if (_byId.TryGetValue(claimant, out var other) && !other.Quarantined)
                                _byId[claimant] = other with { Quarantined = true };
                        }
                }
            }

            var entryId = mac ?? $"ip:{ipText}";
            _byId.TryGetValue(entryId, out var existing);
            // Cross-key witness: this IP was last filed under a
            // DIFFERENT identity (MAC changed under a stable IP).
            CensusEntry? ipPrevious = null;
            if (_entryIdByIp.TryGetValue(ipText, out var prevId) && prevId != entryId)
                _byId.TryGetValue(prevId, out ipPrevious);

            var drift = new List<string>();
            if (existing is not null)
            {
                if (!string.Equals(existing.IpAddress, ipText, StringComparison.OrdinalIgnoreCase))
                {
                    drift.Add(CensusDriftKinds.IpChanged);
                    // FIX (D38 F5): the identity has LEFT its old
                    // IP — drop the stale ip→entry mapping now, or
                    // the next device to legitimately take that IP
                    // (ordinary DHCP reuse) is accused of a
                    // mac_changed swap against a device that is no
                    // longer there.
                    if (_entryIdByIp.TryGetValue(existing.IpAddress, out var oldId) &&
                        string.Equals(oldId, entryId, StringComparison.OrdinalIgnoreCase))
                        _entryIdByIp.Remove(existing.IpAddress);
                }
                if (!string.Equals(existing.Fingerprint, fingerprint, StringComparison.Ordinal))
                    drift.Add(CensusDriftKinds.FingerprintChanged);
            }
            // The MacChanged witness only fires when the previous
            // identity STILL sits at this IP — a mapping that names
            // an entry which has since moved away proves nothing.
            if (ipPrevious is not null && mac is not null &&
                string.Equals(ipPrevious.IpAddress, ipText, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ipPrevious.MacAddress ?? "", mac, StringComparison.OrdinalIgnoreCase))
                drift.Add(CensusDriftKinds.MacChanged);
            if (poisoned)
            {
                drift.Add(_sweepMacIps.TryGetValue(mac ?? "", out var manyIps) && manyIps.Count > MaxIpsPerMacPerSweep
                    ? CensusDriftKinds.MacClaimedManyIps : CensusDriftKinds.IpClaimedByManyMacs);
            }

            // FIX (D38 F3): quarantine is a THIS-SWEEP state, not a
            // life sentence. The old sticky flag silenced an
            // identity forever — a rogue that claimed 5 IPs once
            // stayed silent on every later sweep, and an attacker
            // answering 5 in-scope IPs with a VICTIM's MAC locked
            // the victim out of landing and drift alerting with no
            // way back. Now: quarantined iff this sweep's witness
            // names the identity; a later clean sweep files, lands
            // and alerts normally again. ClearQuarantine (below) is
            // the admin path inside the same sweep.
            var quarantined = mac is not null && _sweepQuarantinedMacs.Contains(mac);
            var (make, model) = GuessMakeModel(obs);
            var flags = new HashSet<string>(existing?.DriftFlags ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            foreach (var d in drift) flags.Add(d);

            if (existing is null && _byId.Count >= MaxEntries)
            {
                // FIX (D38 F7): make room from STALE evidence first
                // (see StaleEvictionAge) — only a census full of
                // fresh entries refuses the new identity.
                var stale = _byId.Values
                    .Where(e => now - e.LastSeenUtc >= StaleEvictionAge)
                    .OrderBy(e => e.LastSeenUtc).FirstOrDefault();
                if (stale is null)
                    return new CensusUpsertResult(CensusUpsertResult.Refused, null,
                        Array.Empty<string>(), $"census is full ({MaxEntries}) — refused");
                _byId.Remove(stale.EntryId);
                if (_entryIdByIp.TryGetValue(stale.IpAddress, out var staleId) &&
                    string.Equals(staleId, stale.EntryId, StringComparison.OrdinalIgnoreCase))
                    _entryIdByIp.Remove(stale.IpAddress);
            }

            var entry = new CensusEntry(
                entryId, ipText, mac, fingerprint,
                DeviceFingerprint.GuessKind(obs),
                make ?? existing?.Make, model ?? existing?.Model,
                existing?.FirstSeenUtc ?? now, now,
                (existing?.SweepCount ?? 0) + 1,
                quarantined,
                flags.OrderBy(f => f, StringComparer.Ordinal).ToList());
            _byId[entryId] = entry;
            _entryIdByIp[ipText] = entryId;

            var outcome = quarantined ? CensusUpsertResult.Quarantined
                : existing is null ? CensusUpsertResult.Added
                : drift.Count > 0 ? CensusUpsertResult.Drift
                : CensusUpsertResult.Updated;
            return new CensusUpsertResult(outcome, entry, drift,
                outcome == CensusUpsertResult.Added ? "new device filed in the census"
                : outcome == CensusUpsertResult.Quarantined ? "identity quarantined: poisoning witness tripped this sweep"
                : drift.Count > 0 ? $"identity drift: {string.Join(",", drift)}"
                : "known device re-seen");
        }
    }

    /// <summary>Admin unquarantine (FIX D38 F3): clears an entry's
    /// quarantine flag and this sweep's witness mark for its MAC.
    /// The drift FLAGS stay — they are history, not state. Returns
    /// false when the entry does not exist. (An identity that is
    /// STILL tripping the witness this sweep re-quarantines on its
    /// next claim — clearing is not a laundering path.)</summary>
    public bool ClearQuarantine(string entryId)
    {
        lock (_gate)
        {
            if (entryId is null || !_byId.TryGetValue(entryId, out var e)) return false;
            if (e.MacAddress is not null) _sweepQuarantinedMacs.Remove(e.MacAddress);
            if (e.Quarantined) _byId[entryId] = e with { Quarantined = false };
            return true;
        }
    }

    /// <summary>Make/model from SNMP facts, stated only when the
    /// device itself said so: sysDescr's first segment is the
    /// vendor string on most gear; model extraction beyond that is
    /// vendor-specific and is NOT guessed here (null = not stated).</summary>
    private static (string? Make, string? Model) GuessMakeModel(ProbeObservation obs)
    {
        var descr = obs.Snmp?.SysDescr?.Trim();
        if (string.IsNullOrEmpty(descr)) return (null, null);
        var first = descr.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return (first, null);
    }
}

// ---- topology (MODEL only — rendering is design-phase) ---------------------

public static class TopologyNodeKinds
{
    public const string Probe = "probe";
    public const string Switch = "network-switch";
    public const string Device = "device";
}

public static class TopologyEdgeKinds
{
    public const string Uplink = "uplink";         // node connects through the other (switch port evidence)
    public const string SameSubnet = "same-subnet"; // L3 adjacency: both filed in one probed subnet
    public const string DiscoveredBy = "discovered-by";
}

public sealed record TopologyNode(string Id, string Kind, string Label, string? IpAddress, string? MacAddress);

public sealed record TopologyEdge(string FromId, string ToId, string Kind, string Evidence);

/// <summary>The site topology as DATA: nodes (probe, switches,
/// census devices) and edges (uplink evidence from SNMP bridge
/// tables, subnet adjacency, discovery provenance). Forgery
/// discipline: an edge naming an unknown node, a self-loop, or an
/// unknown edge kind is REFUSED — a topology that can be drawn
/// from invented relationships is worse than none.</summary>
public sealed class TopologyGraph
{
    private readonly Dictionary<string, TopologyNode> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<TopologyEdge> _edges = new();
    private readonly HashSet<string> _edgeKeys = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<TopologyNode> Nodes => _nodes.Values.OrderBy(n => n.Id, StringComparer.Ordinal).ToList();
    public IReadOnlyList<TopologyEdge> Edges => _edges.ToList();

    public bool AddNode(TopologyNode node)
    {
        if (node is null || string.IsNullOrWhiteSpace(node.Id)) return false;
        if (_nodes.ContainsKey(node.Id)) return false;
        _nodes[node.Id] = node;
        return true;
    }

    public bool AddEdge(TopologyEdge edge)
    {
        if (edge is null) return false;
        if (edge.Kind is not (TopologyEdgeKinds.Uplink or TopologyEdgeKinds.SameSubnet or TopologyEdgeKinds.DiscoveredBy))
            return false;
        if (string.Equals(edge.FromId, edge.ToId, StringComparison.OrdinalIgnoreCase)) return false; // self-loop
        if (!_nodes.ContainsKey(edge.FromId ?? "") || !_nodes.ContainsKey(edge.ToId ?? "")) return false; // forgery: unknown endpoint
        var key = $"{edge.FromId}|{edge.ToId}|{edge.Kind}";
        if (!_edgeKeys.Add(key)) return false; // duplicate
        _edges.Add(edge);
        return true;
    }

    /// <summary>Build the graph from a census snapshot + link hints
    /// (fromId→toId pairs carrying switch-port evidence, e.g. an
    /// SNMP bridge-table read: "MAC X is on switch Y port 12").
    /// Hints naming devices outside the census are dropped by the
    /// AddEdge forgery rule, never filed.</summary>
    public static TopologyGraph Build(
        string probeNodeId, string probeLabel,
        IReadOnlyList<CensusEntry> census,
        IEnumerable<(string FromId, string ToId, string Evidence)>? uplinkHints = null)
    {
        var g = new TopologyGraph();
        g.AddNode(new TopologyNode(probeNodeId, TopologyNodeKinds.Probe, probeLabel, null, null));
        foreach (var e in census)
        {
            var kind = e.KindGuess == "network-switch" ? TopologyNodeKinds.Switch : TopologyNodeKinds.Device;
            g.AddNode(new TopologyNode(e.EntryId, kind, e.EntryId, e.IpAddress, e.MacAddress));
            g.AddEdge(new TopologyEdge(e.EntryId, probeNodeId, TopologyEdgeKinds.DiscoveredBy, "rmm11-discovery sweep"));
        }
        foreach (var (from, to, evidence) in uplinkHints ?? Array.Empty<(string, string, string)>())
            g.AddEdge(new TopologyEdge(from, to, TopologyEdgeKinds.Uplink, evidence));
        // FIX (D38 F12a): NO subnet-adjacency edges are drawn.
        // The old build connected every device to the PROBE with a
        // hard-coded "/24" label — an invented relationship (the
        // devices were never shown to share a subnet with the
        // probe, and the scope's real prefix was never consulted),
        // exactly the fabricated edge this graph's forgery rule
        // exists to refuse. SameSubnet edges enter only when a
        // caller supplies them as evidence-backed hints, like
        // Uplink hints; Build itself asserts only DiscoveredBy.
        return g;
    }
}
