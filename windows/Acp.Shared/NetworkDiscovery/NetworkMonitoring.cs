using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Acp.Shared.NetworkDiscovery;

// =====================================================================
// RMM-11 — agentless monitoring parsers + config backup. Every
// parser here is a PURE function over byte fixtures (the test
// discipline: no real network anywhere in tests) and a SECURITY
// boundary: hostile input — lying lengths, overflowing integers,
// floods of varbinds — degrades to a named parse failure or a
// bounded partial result, never an exception escaping, never an
// unbounded allocation, never a fabricated reading.
// =====================================================================

// ---- SNMP ------------------------------------------------------------------

public static class SnmpOids
{
    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string IfOperStatusPrefix = "1.3.6.1.2.1.2.2.1.8";       // .<ifIndex>: 1=up 2=down
    public const string PrinterSuppliesLevelPrefix = "1.3.6.1.2.1.43.11.1.1.9"; // prtMarkerSuppliesLevel .1.1.<n>
    public const string UpsBatteryCharge = "1.3.6.1.2.1.33.1.2.4.0";      // upsEstimatedChargeRemaining %
    public const string UpsOnBattery = "1.3.6.1.2.1.33.1.2.2.0";          // upsBatteryStatus: 2=onBattery
}

/// <summary>One SNMP varbind. Value is the textual form; numeric
/// interpretation happens in the evaluator with overflow guards —
/// a varbind that CLAIMS an impossible integer is data, not a
/// crash.</summary>
public sealed record SnmpVarBind(string Oid, string Type, string Value);

public sealed record SnmpParseResult(
    bool Ok, string? Error, IReadOnlyList<SnmpVarBind> VarBinds, int DroppedLines)
{
    public IReadOnlyList<SnmpVarBind> VarBinds { get; init; } = VarBinds ?? Array.Empty<SnmpVarBind>();
}

/// <summary>The SNMP fixture parser. Fixture wire form (the shape
/// the collectors normalize real SNMP reads into, and the shape
/// tests feed): UTF-8 lines `oid|type|value`, one varbind per
/// line. Bounds: 256 KB total, 512 varbinds, 1024 chars per line,
/// OID shape strictly dotted-numeric. Malformed lines are dropped
/// and COUNTED — a partial read is reported as partial, never
/// silently completed.</summary>
public static class SnmpFixtureParser
{
    public const int MaxBytes = 256 * 1024;
    public const int MaxVarBinds = 512;
    public const int MaxLineLength = 1024;

    public static SnmpParseResult Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxBytes)
            return new SnmpParseResult(false, $"snmp fixture exceeds {MaxBytes} bytes — refused", Array.Empty<SnmpVarBind>(), 0);
        string text;
        try { text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes); }
        catch { return new SnmpParseResult(false, "snmp fixture is not valid UTF-8 — refused", Array.Empty<SnmpVarBind>(), 0); }

        var binds = new List<SnmpVarBind>();
        var dropped = 0;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;
            if (line.Length > MaxLineLength) { dropped++; continue; }
            var parts = line.Split('|', 3);
            if (parts.Length != 3 || !IsOid(parts[0].Trim()) ||
                parts[1].Trim().Length is 0 or > 32 || parts[2].Length > 512)
            { dropped++; continue; }
            if (binds.Count >= MaxVarBinds) { dropped++; continue; }
            binds.Add(new SnmpVarBind(parts[0].Trim(), parts[1].Trim(), parts[2]));
        }
        return new SnmpParseResult(true, null, binds, dropped);
    }

    public static bool IsOid(string? s)
    {
        if (string.IsNullOrEmpty(s) || s.Length > 128) return false;
        var arcs = s.Split('.');
        if (arcs.Length < 2) return false;
        foreach (var arc in arcs)
        {
            if (arc.Length == 0 || arc.Length > 10) return false;
            if (!arc.All(char.IsDigit)) return false;
            if (!long.TryParse(arc, out var v) || v < 0 || v > 4294967295L) return false;
        }
        return true;
    }
}

/// <summary>One SNMP trap, parsed from the same fixture form with a
/// leading `TRAP|enterprise|agentIp|generic|specific` header line.</summary>
public sealed record SnmpTrap(string EnterpriseOid, string AgentIp, int Generic, int Specific,
    IReadOnlyList<SnmpVarBind> VarBinds, DateTimeOffset ReceivedUtc);

public static class SnmpTrapParser
{
    public static SnmpTrap? Parse(ReadOnlySpan<byte> bytes, DateTimeOffset receivedUtc)
    {
        var result = SnmpFixtureParser.Parse(bytes);
        if (!result.Ok) return null;
        string text;
        try { text = Encoding.UTF8.GetString(bytes); } catch { return null; }
        var header = text.Split('\n').FirstOrDefault()?.TrimEnd('\r') ?? "";
        var parts = header.Split('|');
        if (parts.Length != 5 || parts[0] != "TRAP") return null;
        if (!SnmpFixtureParser.IsOid(parts[1].Trim())) return null;
        if (!IPAddress.TryParse(parts[2].Trim(), out var agent) ||
            !NetworkAddressing.IsProbeableHost(agent)) return null; // a trap "from" loopback/metadata is not a trap
        agent = NetworkAddressing.UnwrapMapped(agent);
        // FIX (D38 F10): trap-type fields are bounded by the
        // protocol — generic-trap is 0..6 (SNMPv1), specific-trap
        // is a non-negative enterprise code. Unbounded/negative
        // values are not traps.
        if (!int.TryParse(parts[3], out var generic) || generic < 0 || generic > 6 ||
            !int.TryParse(parts[4], out var specific) || specific < 0) return null;
        // Varbinds follow the header: re-parse the remainder so the
        // header line itself never becomes a varbind.
        var nl = text.IndexOf('\n');
        var rest = nl >= 0 ? text[(nl + 1)..] : "";
        var binds = SnmpFixtureParser.Parse(Encoding.UTF8.GetBytes(rest));
        return new SnmpTrap(parts[1].Trim(), agent.ToString(), generic, specific,
            binds.VarBinds, receivedUtc);
    }
}

// ---- SNMP threshold evaluation ----------------------------------------------

public static class SnmpFindingKinds
{
    public const string TonerLow = "toner_low";
    public const string BatteryLow = "battery_low";
    public const string OnBattery = "on_battery";
    public const string PortDown = "port_down";
    public const string CustomBelow = "custom_below";
    public const string CustomAbove = "custom_above";
}

public sealed record SnmpFinding(string Kind, string Oid, string Detail, string Severity);

/// <summary>One admin/vendor OID watch rule: a numeric OID whose
/// value crossing a threshold is a finding. Custom OIDs are how a
/// site watches the one weird box only it owns.</summary>
public sealed record SnmpOidRule(string Oid, string Direction, long Threshold, string Severity, string Label)
{
    public const string Below = "below";
    public const string Above = "above";
}

/// <summary>Pure evaluation of one device's SNMP readings: the
/// vendor facts (toner %, UPS charge/status, port oper status) plus
/// admin custom-OID rules. A reading that is absent evaluates to
/// NOTHING — silence is not health and not a finding; a reading
/// that does not parse as a number is skipped, never guessed.</summary>
public static class SnmpMonitorEvaluator
{
    public const long TonerLowPercent = 15;
    public const long BatteryLowPercent = 30;

    public static IReadOnlyList<SnmpFinding> Evaluate(
        IReadOnlyList<SnmpVarBind> binds, IReadOnlyList<SnmpOidRule>? customRules = null)
    {
        var findings = new List<SnmpFinding>();
        long? Num(string oid) => binds.FirstOrDefault(b => b.Oid == oid) is { } b &&
            long.TryParse(b.Value.Trim(), out var v) ? v : null;

        foreach (var b in binds)
        {
            if (b.Oid.StartsWith(SnmpOids.PrinterSuppliesLevelPrefix + ".", StringComparison.Ordinal) &&
                long.TryParse(b.Value.Trim(), out var level))
            {
                // prtMarkerSuppliesLevel: -1/-2/-3 are sentinel
                // "unknown/some remaining" values, not percentages.
                if (level >= 0 && level <= TonerLowPercent)
                    findings.Add(new SnmpFinding(SnmpFindingKinds.TonerLow, b.Oid,
                        $"printer supply level {level}% at {b.Oid} (threshold {TonerLowPercent}%)", "warning"));
            }
            if (b.Oid.StartsWith(SnmpOids.IfOperStatusPrefix + ".", StringComparison.Ordinal) &&
                long.TryParse(b.Value.Trim(), out var oper) && oper != 1)
                findings.Add(new SnmpFinding(SnmpFindingKinds.PortDown, b.Oid,
                    $"interface oper status {oper} at {b.Oid} (1=up)", "warning"));
        }
        if (Num(SnmpOids.UpsBatteryCharge) is { } charge && charge <= BatteryLowPercent)
            findings.Add(new SnmpFinding(SnmpFindingKinds.BatteryLow, SnmpOids.UpsBatteryCharge,
                $"UPS estimated charge {charge}% (threshold {BatteryLowPercent}%)", "warning"));
        if (Num(SnmpOids.UpsOnBattery) is { } batt && batt == 2)
            findings.Add(new SnmpFinding(SnmpFindingKinds.OnBattery, SnmpOids.UpsOnBattery,
                "UPS is ON BATTERY", "critical"));

        foreach (var rule in customRules ?? Array.Empty<SnmpOidRule>())
        {
            if (Num(rule.Oid) is not { } v) continue;
            if (rule.Direction == SnmpOidRule.Below && v < rule.Threshold)
                findings.Add(new SnmpFinding(SnmpFindingKinds.CustomBelow, rule.Oid,
                    $"{rule.Label}: {v} < {rule.Threshold}", rule.Severity));
            else if (rule.Direction == SnmpOidRule.Above && v > rule.Threshold)
                findings.Add(new SnmpFinding(SnmpFindingKinds.CustomAbove, rule.Oid,
                    $"{rule.Label}: {v} > {rule.Threshold}", rule.Severity));
        }
        return findings;
    }
}

// ---- syslog -------------------------------------------------------------------

public sealed record SyslogMessage(
    int Facility, int Severity, string? Hostname, string Tag, string Message, string RawHeader);

public sealed record SyslogKeywordRule(string Keyword, string Severity);

/// <summary>RFC 3164-shaped syslog parsing + keyword alerting.
/// Pure and bounded: an unparseable line is null (counted by the
/// caller), never a fabricated message. Severity follows syslog:
/// 0 emerg … 7 debug.</summary>
public static class SyslogParser
{
    public const int MaxLineLength = 4096;

    public static SyslogMessage? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength) return null;
        var s = line.Trim();
        if (!s.StartsWith("<")) return null;
        var close = s.IndexOf('>');
        if (close < 2 || close > 4) return null;
        // FIX (D38 F10): PRI is digits only — the default
        // NumberStyles.Integer also accepted a sign and whitespace
        // ("<+9>", "< 9>"), which are not syslog priorities.
        if (!int.TryParse(s.AsSpan(1, close - 1), NumberStyles.None,
                CultureInfo.InvariantCulture, out var pri) || pri < 0 || pri > 191) return null;
        var rest = s[(close + 1)..];
        // Header: "Mmm dd hh:mm:ss hostname tag: message" — the
        // timestamp is 15 chars in 3164 form; we keep it raw and
        // split hostname/tag structurally, tolerating a missing tag.
        string? hostname = null; var tag = ""; var message = rest.Trim();
        // FIX (D38 F9): the hostname is only split out when the
        // 3164 timestamp shape is actually present at the expected
        // offsets AND the token is hostname-shaped. The old code
        // took whatever sat at offset 16 of ANY line as the
        // "hostname" — free attacker text that then became the
        // subject (DeviceId) of centre alerts. A line that does
        // not carry the shape parses with hostname = null and the
        // service alerts on the neutral "syslog" subject.
        if (rest.Length > 16 && rest[3] == ' ' && rest[6] == ' ' &&
            rest[9] == ':' && rest[12] == ':' && rest[15] == ' ')
        {
            var afterTs = rest[16..];
            var sp = afterTs.IndexOf(' ');
            if (sp > 0)
            {
                var candidate = afterTs[..sp];
                if (IsHostnameToken(candidate))
                {
                    hostname = candidate;
                    var remainder = afterTs[(sp + 1)..];
                    var colon = remainder.IndexOf(':');
                    if (colon > 0 && colon < 64)
                    {
                        tag = remainder[..colon].Trim();
                        message = remainder[(colon + 1)..].Trim();
                    }
                    else message = remainder.Trim();
                }
            }
        }
        return new SyslogMessage(pri / 8, pri % 8, hostname, tag, message, s[..(close + 1)]);
    }

    /// <summary>A hostname token: 1–63 chars of letters, digits,
    /// '-' and '.', not starting or ending with a separator. Free
    /// text failing this shape is never promoted to an alert
    /// subject (FIX D38 F9).</summary>
    private static bool IsHostnameToken(string token) =>
        token.Length is >= 1 and <= 63 &&
        token.All(c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '.') &&
        !token.StartsWith('-') && !token.StartsWith('.') &&
        !token.EndsWith('-') && !token.EndsWith('.');

    /// <summary>Keyword evaluation: case-insensitive substring over
    /// the message body. At most one finding per rule per message.</summary>
    public static IReadOnlyList<(SyslogKeywordRule Rule, SyslogMessage Message)> MatchKeywords(
        SyslogMessage message, IReadOnlyList<SyslogKeywordRule> rules)
    {
        var hits = new List<(SyslogKeywordRule, SyslogMessage)>();
        foreach (var rule in rules.Take(128))
        {
            if (string.IsNullOrWhiteSpace(rule.Keyword)) continue;
            if (message.Message.Contains(rule.Keyword, StringComparison.OrdinalIgnoreCase))
                hits.Add((rule, message));
        }
        return hits;
    }
}

// ---- flow (NetFlow v5 + sFlow summaries) ---------------------------------------

public sealed record FlowRecord(
    string SrcAddr, string DstAddr, long Packets, long Octets, int SrcPort, int DstPort, int Protocol);

public sealed record FlowSummary(
    int FlowCount, long TotalOctets, long TotalPackets,
    IReadOnlyList<(string Address, long Octets)> TopTalkers,
    IReadOnlyList<FlowRecord> Flows)
{
    public IReadOnlyList<FlowRecord> Flows { get; init; } = Flows ?? Array.Empty<FlowRecord>();
    public IReadOnlyList<(string Address, long Octets)> TopTalkers { get; init; } =
        TopTalkers ?? Array.Empty<(string, long)>();
}

/// <summary>NetFlow v5 parser over the REAL binary wire format
/// (24-byte header, 48-byte records). Bounds: the header's count
/// must match the bytes present (a lying count is refused, not
/// clamped into fabricated flows), version must be 5, at most
/// 1024 records per datagram.</summary>
public static class NetFlowV5Parser
{
    public const int HeaderBytes = 24;
    public const int RecordBytes = 48;
    public const int MaxRecords = 1024;

    public static FlowSummary? Parse(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < HeaderBytes) return null;
        var version = BinaryPrimitives.ReadUInt16BigEndian(datagram);
        if (version != 5) return null;
        var count = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        if (count == 0 || count > MaxRecords) return null;
        // FIX (D38 F10): the count must match the bytes EXACTLY —
        // a datagram carrying MORE than count×48 record bytes is
        // as malformed as one carrying fewer; trailing bytes are
        // refused, not silently ignored.
        if (datagram.Length != HeaderBytes + count * RecordBytes) return null; // count lies about the bytes
        var flows = new List<FlowRecord>(count);
        for (var i = 0; i < count; i++)
        {
            var r = datagram.Slice(HeaderBytes + i * RecordBytes, RecordBytes);
            flows.Add(new FlowRecord(
                new IPAddress(r[..4]).ToString(),
                new IPAddress(r.Slice(4, 4)).ToString(),
                BinaryPrimitives.ReadUInt32BigEndian(r.Slice(16, 4)),
                BinaryPrimitives.ReadUInt32BigEndian(r.Slice(20, 4)),
                BinaryPrimitives.ReadUInt16BigEndian(r.Slice(32, 2)),
                BinaryPrimitives.ReadUInt16BigEndian(r.Slice(34, 2)),
                r[38]));
        }
        return FlowAggregator.Summarize(flows);
    }
}

/// <summary>sFlow input shape: sampled records the collector
/// normalized (the sFlow datagram decode itself is collector
/// wiring; the SUMMARY is the model's job and is shared).</summary>
public sealed record SflowSample(string AgentIp, string SrcAddr, string DstAddr, long Octets, int Protocol);

public static class FlowAggregator
{
    public const int TopTalkerCount = 10;

    public static FlowSummary Summarize(IReadOnlyList<FlowRecord> flows)
    {
        var bySrc = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        long octets = 0, packets = 0;
        // FIX (D38 F10): sums saturate instead of wrapping — an
        // unchecked long sum over hostile samples could roll
        // negative and invert top-talker order.
        static long SatAdd(long a, long b)
        {
            try { return checked(a + b); } catch (OverflowException) { return long.MaxValue; }
        }
        foreach (var f in flows)
        {
            octets = SatAdd(octets, f.Octets); packets = SatAdd(packets, f.Packets);
            bySrc[f.SrcAddr] = SatAdd(bySrc.GetValueOrDefault(f.SrcAddr), f.Octets);
        }
        var top = bySrc.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal)
            .Take(TopTalkerCount).Select(kv => (kv.Key, kv.Value)).ToList();
        return new FlowSummary(flows.Count, octets, packets, top, flows);
    }

    /// <summary>FIX (D38 F10): sFlow samples with a negative octet
    /// count are invalid samples — dropped before aggregation,
    /// never summed into a smaller total.</summary>
    public static FlowSummary SummarizeSflow(IReadOnlyList<SflowSample> samples) =>
        Summarize(samples.Where(s => s.Octets >= 0)
            .Select(s => new FlowRecord(s.SrcAddr, s.DstAddr, 0, s.Octets, 0, 0, s.Protocol)).ToList());
}

// ---- network-device config backup ----------------------------------------------

/// <summary>The config fetcher's exit door: one fetch of one
/// device's running config through its management interface
/// (SSH/HTTPS — the transport is the fetcher's business; the model
/// sees content or a named failure). Tests drive the fake.</summary>
public interface IConfigFetcher
{
    (bool Ok, string? Content, string? Error) Fetch(string deviceId, string managementAddress);
}

/// <summary>Recording fake config fetcher (house pattern).</summary>
public sealed class FakeConfigFetcher : IConfigFetcher
{
    private readonly Dictionary<string, (bool, string?, string?)> _script = new(StringComparer.OrdinalIgnoreCase);
    public List<string> FetchedDeviceIds { get; } = new();

    public FakeConfigFetcher Script(string deviceId, string content)
    {
        _script[deviceId] = (true, content, null);
        return this;
    }

    public FakeConfigFetcher ScriptFailure(string deviceId, string error)
    {
        _script[deviceId] = (false, null, error);
        return this;
    }

    public (bool Ok, string? Content, string? Error) Fetch(string deviceId, string managementAddress)
    {
        FetchedDeviceIds.Add(deviceId);
        return _script.TryGetValue(deviceId, out var r) ? r : (false, null, "no scripted config (fake)");
    }
}

public sealed record ConfigDiff(
    bool Changed, IReadOnlyList<string> AddedLines, IReadOnlyList<string> RemovedLines, string Summary)
{
    public IReadOnlyList<string> AddedLines { get; init; } = AddedLines ?? Array.Empty<string>();
    public IReadOnlyList<string> RemovedLines { get; init; } = RemovedLines ?? Array.Empty<string>();
}

/// <summary>Pure config diff. THE tamper line: change is judged by
/// the content HASH over the raw bytes (only CRLF→LF and ONE
/// missing final newline are normalized — line endings are
/// transport, not content). A comment edit, a whitespace edit, a
/// reordered line, added trailing blank lines, a lone CR: all are
/// CHANGES, because a switch config is exact text and "diffs as
/// unchanged" is precisely the failure this type exists to
/// refuse. The line lists are a multiset difference, capped for
/// display; the verdict never depends on the cap.</summary>
public static class ConfigDiffer
{
    public const int MaxDiffLines = 200;

    // FIX (D38 F11): Normalize previously rewrote lone CR→LF and
    // TrimEnd('\n') deleted ALL trailing newlines, so adding
    // trailing blank lines or changing an embedded CR diffed as
    // UNCHANGED — more normalization than the claim allows. Now:
    // CRLF→LF, and a final newline is supplied only when missing.
    public static string Normalize(string content)
    {
        var s = (content ?? "").Replace("\r\n", "\n");
        return s.EndsWith('\n') ? s : s + "\n";
    }

    public static string ContentHash(string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(content)))).ToLowerInvariant();

    public static ConfigDiff Diff(string oldContent, string newContent)
    {
        var oldHash = ContentHash(oldContent);
        var newHash = ContentHash(newContent);
        if (oldHash == newHash)
            return new ConfigDiff(false, Array.Empty<string>(), Array.Empty<string>(), "unchanged");
        var oldLines = Normalize(oldContent).Split('\n');
        var newLines = Normalize(newContent).Split('\n');
        var removed = MultisetDifference(oldLines, newLines);
        var added = MultisetDifference(newLines, oldLines);
        var summary = $"changed: +{added.Count} -{removed.Count} lines (hash {oldHash[..8]}->{newHash[..8]})";
        return new ConfigDiff(true,
            added.Take(MaxDiffLines).ToList(), removed.Take(MaxDiffLines).ToList(), summary);
    }

    private static List<string> MultisetDifference(string[] a, string[] b)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var line in b) counts[line] = counts.GetValueOrDefault(line) + 1;
        var diff = new List<string>();
        foreach (var line in a)
        {
            if (counts.TryGetValue(line, out var c) && c > 0) counts[line] = c - 1;
            else diff.Add(line);
        }
        return diff;
    }
}

public sealed record ConfigVersion(
    string DeviceId, int Version, string Content, string ContentHash,
    string PrevHash, DateTimeOffset FetchedUtc, string Source);

public sealed record ConfigBackupResult(
    string Outcome, ConfigVersion? Version, ConfigDiff? Diff)
{
    public const string FirstVersion = "first_version";
    public const string Unchanged = "unchanged";
    public const string Changed = "changed";
    public const string Refused = "refused";
}

/// <summary>Versioned config store: every fetch is hashed, chained
/// to the previous version's hash (a tampered history breaks the
/// chain visibly), and diffed. Retention is bounded per device.
/// Export/import re-verify every hash: an entry whose content no
/// longer hashes to its recorded hash imports as REFUSED and is
/// counted — backup tampering cannot launder itself through a
/// restore.</summary>
public sealed class ConfigBackupStore
{
    public const int MaxVersionsPerDevice = 32;
    public const int MaxContentBytes = 1024 * 1024;
    public const string GenesisHash = "GENESIS";

    private readonly Dictionary<string, List<ConfigVersion>> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ConfigBackupResult Backup(string deviceId, string content, string source, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return new ConfigBackupResult(ConfigBackupResult.Refused, null, null);
        if (content is null || Encoding.UTF8.GetByteCount(content) > MaxContentBytes)
            return new ConfigBackupResult(ConfigBackupResult.Refused, null, null);
        lock (_gate)
        {
            var list = _byDevice.TryGetValue(deviceId, out var l) ? l : _byDevice[deviceId] = new List<ConfigVersion>();
            var prev = list.LastOrDefault();
            var hash = ConfigDiffer.ContentHash(content);
            if (prev is not null && prev.ContentHash == hash)
                return new ConfigBackupResult(ConfigBackupResult.Unchanged, prev, ConfigDiffer.Diff(prev.Content, content));
            var version = new ConfigVersion(deviceId, (prev?.Version ?? 0) + 1, content, hash,
                prev?.ContentHash ?? GenesisHash, now, source);
            list.Add(version);
            while (list.Count > MaxVersionsPerDevice) list.RemoveAt(0);
            if (prev is null)
                return new ConfigBackupResult(ConfigBackupResult.FirstVersion, version, null);
            return new ConfigBackupResult(ConfigBackupResult.Changed, version, ConfigDiffer.Diff(prev.Content, content));
        }
    }

    public ConfigVersion? Latest(string deviceId)
    {
        lock (_gate) return deviceId is not null && _byDevice.TryGetValue(deviceId, out var l) ? l.LastOrDefault() : null;
    }

    public IReadOnlyList<ConfigVersion> Versions(string deviceId)
    {
        lock (_gate) return deviceId is not null && _byDevice.TryGetValue(deviceId, out var l)
            ? l.ToList() : Array.Empty<ConfigVersion>();
    }

    /// <summary>Re-verify one device's stored chain: every
    /// version's content must hash to its recorded hash and link
    /// to its predecessor. False names a broken chain — tampering
    /// with stored content (or its hashes) is DETECTED here, never
    /// absorbed.</summary>
    public (bool Ok, string Detail) VerifyIntegrity(string deviceId)
    {
        lock (_gate)
        {
            if (deviceId is null || !_byDevice.TryGetValue(deviceId, out var list) || list.Count == 0)
                return (true, "no versions stored");
            // The oldest RETAINED version anchors the window: its
            // PrevHash names a version retention may have dropped,
            // so the window's first link is checked by content only.
            for (var i = 0; i < list.Count; i++)
            {
                var v = list[i];
                if (ConfigDiffer.ContentHash(v.Content) != v.ContentHash)
                    return (false, $"version {v.Version}: content does not hash to its recorded hash — TAMPERED");
                if (i > 0 && v.PrevHash != list[i - 1].ContentHash)
                    return (false, $"version {v.Version}: prev-hash link broken — history rewritten");
            }
            return (true, $"{list.Count} versions verified");
        }
    }

    // ---- persistence (DTO discipline, house pattern) -------------

    private sealed record VersionDto(string DeviceId, int Version, string Content, string ContentHash,
        string PrevHash, DateTimeOffset FetchedUtc, string Source);

    public string ExportJson()
    {
        lock (_gate)
        {
            var dtos = _byDevice.Values.SelectMany(l => l)
                .Select(v => new VersionDto(v.DeviceId, v.Version, v.Content, v.ContentHash, v.PrevHash, v.FetchedUtc, v.Source))
                .ToArray();
            return System.Text.Json.JsonSerializer.Serialize(dtos);
        }
    }

    /// <summary>Restore versions. Returns (restored, refusedTampered).
    /// An entry whose content does not hash to its recorded hash is
    /// REFUSED and counted — it never enters the store.
    /// FIX (D38 F4): the per-entry hash check alone was recompute-
    /// and-pass — an editor who recomputed ContentHash after
    /// editing imported cleanly. Import now ALSO verifies the
    /// hash CHAIN: each version's PrevHash must name the previous
    /// version's ContentHash (the previous entry in this import,
    /// or the version already stored under version−1), so editing
    /// any version breaks its SUCCESSOR's link and the successor
    /// is refused. The 1 MB content cap and the 32-version
    /// retention are enforced on import too — a restore can no
    /// longer mint an unbounded, oversized history. (Residual,
    /// named: the chain is unkeyed SHA-256, so a rewrite of EVERY
    /// version with a fully recomputed chain is indistinguishable
    /// from a genuine export — detecting that needs a keyed HMAC
    /// or an external hash anchor, which this store does not have;
    /// VerifyIntegrity carries the same bound.)</summary>
    public (int Restored, int RefusedTampered) ImportJson(string json)
    {
        VersionDto[]? dtos;
        try { dtos = System.Text.Json.JsonSerializer.Deserialize<VersionDto[]>(json); }
        catch { return (0, 0); }
        if (dtos is null) return (0, 0);
        var restored = 0; var refused = 0;
        lock (_gate)
        {
            string? prevDevice = null; string? prevHash = null;
            foreach (var dto in dtos.OrderBy(d => d.DeviceId, StringComparer.Ordinal).ThenBy(d => d.Version))
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.DeviceId)) continue;
                if (dto.Content is null ||
                    Encoding.UTF8.GetByteCount(dto.Content) > MaxContentBytes ||
                    ConfigDiffer.ContentHash(dto.Content) != dto.ContentHash) { refused++; continue; }
                var list = _byDevice.TryGetValue(dto.DeviceId, out var l) ? l : _byDevice[dto.DeviceId] = new List<ConfigVersion>();
                if (list.Any(v => v.Version == dto.Version)) continue;
                // Chain link: the expected predecessor is the last
                // accepted entry for this device in this import, or
                // the stored version dto.Version−1 when the import
                // continues an existing history. A window's first
                // entry (predecessor retention-dropped / not in
                // this import) is unchecked, mirroring
                // VerifyIntegrity's window rule.
                var expectedPrev = string.Equals(prevDevice, dto.DeviceId, StringComparison.OrdinalIgnoreCase)
                    ? prevHash
                    : list.FirstOrDefault(v => v.Version == dto.Version - 1)?.ContentHash;
                if (expectedPrev is not null && dto.PrevHash != expectedPrev) { refused++; continue; }
                list.Add(new ConfigVersion(dto.DeviceId, dto.Version, dto.Content, dto.ContentHash,
                    dto.PrevHash, dto.FetchedUtc, dto.Source));
                list.Sort((a, b) => a.Version.CompareTo(b.Version));
                while (list.Count > MaxVersionsPerDevice) list.RemoveAt(0); // retention applies to restores too
                prevDevice = dto.DeviceId; prevHash = dto.ContentHash;
                restored++;
            }
        }
        return (restored, refused);
    }
}
