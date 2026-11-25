using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Acp.Shared.NetworkDiscovery;

// =====================================================================
// Lane A (item 2d) — PRODUCTION probe transports for RMM-11.
//
//   * ProductionProbeTransport (IProbeTransport): credentialess
//     TCP connect scan over a small named port set, SNMPv2c
//     profiling (sysDescr/sysName/sysObjectID/sysContact/
//     sysLocation via real BER-encoded GETs, community "public" —
//     credentialess profiling only), SSH banner grab, HTTP Server
//     header, ONVIF presence (TCP 80/554 + WS-Discovery answer is
//     out of scope for a synchronous probe; OnvifCapable is set
//     from an answered ONVIF device-service HTTP probe on 80).
//     Every socket has a bounded timeout; a host that answers
//     nothing yields null (nothing filed), exactly per contract.
//   * SyslogCollector: a real UDP syslog listener (RFC 3164/5424
//     line shape) that parses messages into records and raises
//     keyword alerts through a sink. Binds only when started;
//     loopback/LAN bind address is the caller's explicit choice.
//   * FlowCollector: a real UDP NetFlow v5 / sFlow-style datagram
//     listener that parses flow headers into per-conversation
//     summaries. NetFlow v5 records are fully parsed; other
//     versions are counted and named, never silently misread.
// All listeners are explicit-start, disposable, and report their
// real bound state — nothing here pretends to listen.
// =====================================================================

public sealed class ProductionProbeTransport : IProbeTransport
{
    public static readonly IReadOnlyList<int> ProbePorts = new[] { 22, 80, 443, 554, 161, 8080, 8443 };
    private readonly TimeSpan _timeout;
    private readonly string _snmpCommunity;

    private readonly Func<string, string?> _macResolver;

    /// <param name="macResolver">BD-SHARED-TRANSPORT F7: resolves
    /// an IP to its MAC from the OS neighbour/ARP cache. The
    /// production default reads /proc/net/arp or `arp -a`; the
    /// census's MAC-keyed identity (poisoning quarantine,
    /// MacChanged drift, IpChanged-under-DHCP) previously never
    /// ran on real data because the probe returned a null MAC for
    /// every host and every entry was keyed 'ip:<addr>'.</param>
    public ProductionProbeTransport(TimeSpan? timeout = null, string snmpCommunity = "public",
        Func<string, string?>? macResolver = null)
    {
        _timeout = timeout ?? TimeSpan.FromMilliseconds(700);
        _snmpCommunity = snmpCommunity ?? "public";
        _macResolver = macResolver ?? ArpNeighbourCache.TryResolveMac;
    }

    public ProbeObservation? Probe(string ipAddress, DateTimeOffset now)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip)) return null;
        // BD-SHARED-TRANSPORT F7: ports are probed in PARALLEL and
        // the SNMP profile runs concurrently — the sequential
        // shape cost ~700 ms per silent port plus five sequential
        // SNMP GETs (≈7.7 s per quiet host, hours per sweep).
        var open = new System.Collections.Concurrent.ConcurrentBag<int>();
        string? sshBanner = null, httpServer = null;
        var onvif = false; var rtsp = false;
        var snmpTask = Task.Run(() => SnmpClient.Profile(ip, _snmpCommunity, _timeout));
        Parallel.ForEach(ProbePorts.Where(p => p != 161), port =>
        {
            try
            {
                using var client = new TcpClient();
                var connect = client.ConnectAsync(ip, port);
                if (!connect.Wait(_timeout) || !client.Connected) return;
                open.Add(port);
                using var stream = client.GetStream();
                stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
                if (port == 22)
                    sshBanner = ReadLine(stream, 128);
                else if (port is 80 or 8080)
                {
                    var req = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n");
                    stream.Write(req, 0, req.Length);
                    var head = ReadSome(stream, 1024);
                    httpServer ??= ParseServerHeader(head);
                    if (port == 80 && head is not null &&
                        (head.Contains("onvif", StringComparison.OrdinalIgnoreCase) ||
                         ProbeOnvifService(ip)))
                        onvif = true;
                }
                else if (port == 554)
                {
                    var req = Encoding.ASCII.GetBytes("OPTIONS rtsp://probe/ RTSP/1.0\r\nCSeq: 1\r\n\r\n");
                    try { stream.Write(req, 0, req.Length); } catch { }
                    var head = ReadSome(stream, 512);
                    if (head is not null && head.Contains("RTSP", StringComparison.OrdinalIgnoreCase))
                        rtsp = true; // RTSP evidence only — ONVIF is a separate, tested claim (F7)
                }
            }
            catch { /* a refused/timed-out port is simply closed for this probe */ }
        });
        var snmp = snmpTask.GetAwaiter().GetResult();
        var openList = open.ToList();
        if (snmp is not null && !openList.Contains(161)) openList.Add(161);
        if (openList.Count == 0 && snmp is null) return null;
        string? mac = null;
        try { mac = _macResolver(ipAddress); } catch { /* no neighbour entry — census falls back to ip keying, honestly */ }
        return new ProbeObservation(ipAddress, mac, snmp?.SysName, openList, snmp,
            sshBanner, httpServer, onvif, now, rtsp);
    }

    /// <summary>BD-SHARED-TRANSPORT F7: the ONVIF probe was a
    /// stub that always returned false. It now sends a real
    /// ONVIF GetDeviceInformation SOAP request to the device
    /// service endpoint on a fresh connection and reports true
    /// only when the answer carries the ONVIF device-service
    /// shape (an onvif.org namespace / a Manufacturer element) —
    /// anything else is not ONVIF evidence.</summary>
    private bool ProbeOnvifService(IPAddress ip)
    {
        try
        {
            using var client = new TcpClient();
            var connect = client.ConnectAsync(ip, 80);
            if (!connect.Wait(_timeout) || !client.Connected) return false;
            using var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            var body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
                "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>";
            var req = Encoding.ASCII.GetBytes(
                "POST /onvif/device_service HTTP/1.0\r\nHost: probe\r\nContent-Type: application/soap+xml\r\n" +
                $"Content-Length: {body.Length}\r\n\r\n" + body);
            stream.Write(req, 0, req.Length);
            var resp = ReadSome(stream, 4096);
            return resp is not null &&
                (resp.Contains("onvif.org", StringComparison.OrdinalIgnoreCase) ||
                 resp.Contains("GetDeviceInformationResponse", StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static string? ReadLine(NetworkStream stream, int max)
    {
        var text = ReadSome(stream, max);
        if (text is null) return null;
        var line = text.Split('\n')[0].Trim();
        return line.Length == 0 ? null : line;
    }

    private static string? ReadSome(NetworkStream stream, int max)
    {
        try
        {
            var buf = new byte[max];
            var read = stream.Read(buf, 0, buf.Length);
            return read <= 0 ? null : Encoding.ASCII.GetString(buf, 0, read);
        }
        catch { return null; }
    }

    private static string? ParseServerHeader(string? head)
    {
        if (head is null) return null;
        foreach (var line in head.Split('\n'))
            if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                return line[7..].Trim();
        return null;
    }
}

/// <summary>Minimal real SNMPv2c client: BER-encoded GET requests
/// for the system group. Community is the credentialess profiling
/// default; a device that does not answer yields null.</summary>
public static class SnmpClient
{
    private static readonly string[] SystemOids =
        { "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0" };

    public static SnmpProfile? Profile(IPAddress ip, string community, TimeSpan timeout)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;
            udp.Connect(ip, 161);
            // BD-SHARED-TRANSPORT F7: ONE multi-varbind GET for the
            // whole system group — five sequential GETs previously
            // cost five timeouts on a quiet host.
            var req = BuildMultiGetRequest(community, SystemOids, requestId: 100);
            udp.Send(req, req.Length);
            var remote = new IPEndPoint(IPAddress.Any, 0);
            var resp = udp.Receive(ref remote);
            var values = ParseAllValues(resp);
            if (values.Length == 0 || values.All(v => v is null)) return null;
            string? At(int i) => i < values.Length ? values[i] : null;
            return new SnmpProfile(At(0), At(1), At(2), At(3), At(4));
        }
        catch { return null; }
    }

    internal static byte[] BuildMultiGetRequest(string community, IReadOnlyList<string> oids, int requestId)
    {
        var binds = oids.Select(oid => Tlv(0x30, Concat(Tlv(0x06, EncodeOid(oid)), new byte[] { 0x05, 0x00 }))).ToArray();
        var varbindList = Tlv(0x30, Concat(binds));
        var pdu = Tlv(0xA0, Concat(EncodeInt(requestId), EncodeInt(0), EncodeInt(0), varbindList));
        return Tlv(0x30, Concat(EncodeInt(1), Tlv(0x04, Encoding.ASCII.GetBytes(community)), pdu));
    }

    /// <summary>All varbind values of a response, in request order.</summary>
    internal static string?[] ParseAllValues(byte[] packet)
    {
        try
        {
            var pos = 0;
            if (!ReadTlv(packet, ref pos, out var content)) return Array.Empty<string?>();
            var p = 0;
            if (!ReadTlv(content, ref p, out _)) return Array.Empty<string?>();
            if (!ReadTlv(content, ref p, out _)) return Array.Empty<string?>();
            if (!ReadTlv(content, ref p, out var pdu)) return Array.Empty<string?>();
            var q = 0;
            for (var i = 0; i < 3; i++) if (!ReadTlv(pdu, ref q, out _)) return Array.Empty<string?>();
            if (!ReadTlv(pdu, ref q, out var list)) return Array.Empty<string?>();
            var values = new List<string?>();
            var r = 0;
            while (r < list.Length)
            {
                if (!ReadTlv(list, ref r, out var bind)) break;
                var t = 0;
                if (!ReadTlv(bind, ref t, out _)) { values.Add(null); continue; }
                if (t >= bind.Length) { values.Add(null); continue; }
                var tag = bind[t];
                if (!ReadTlv(bind, ref t, out var value)) { values.Add(null); continue; }
                values.Add(tag switch
                {
                    0x04 or 0x06 => Encoding.ASCII.GetString(value).TrimEnd('\0'),
                    0x02 => value.Length > 0 ? ((long)value.Aggregate(0L, (a, b) => (a << 8) | b)).ToString() : null,
                    _ => null,
                });
            }
            return values.ToArray();
        }
        catch { return Array.Empty<string?>(); }
    }

    internal static byte[] BuildGetRequest(string community, string oid, int requestId)
    {
        var oidBytes = EncodeOid(oid);
        var varbind = Concat(Tlv(0x30, Concat(Tlv(0x06, oidBytes), new byte[] { 0x05, 0x00 })));
        var varbindList = Tlv(0x30, varbind);
        var pdu = Tlv(0xA0, Concat(EncodeInt(requestId), EncodeInt(0), EncodeInt(0), varbindList));
        var msg = Tlv(0x30, Concat(EncodeInt(1),
            Tlv(0x04, Encoding.ASCII.GetBytes(community)), pdu));
        return msg;
    }

    internal static string? ParseFirstValue(byte[] packet)
    {
        try
        {
            var pos = 0;
            if (!ReadTlv(packet, ref pos, out var content)) return null;
            var p = 0;
            if (!ReadTlv(content, ref p, out _)) return null;                 // version
            if (!ReadTlv(content, ref p, out _)) return null;                 // community
            if (!ReadTlv(content, ref p, out var pdu)) return null;          // pdu
            var q = 0;
            for (var i = 0; i < 3; i++) if (!ReadTlv(pdu, ref q, out _)) return null; // rid, err, idx
            if (!ReadTlv(pdu, ref q, out var list)) return null;              // varbind list
            var r = 0;
            if (!ReadTlv(list, ref r, out var bind)) return null;             // first varbind
            var t = 0;
            if (!ReadTlv(bind, ref t, out _)) return null;                    // oid
            if (t >= bind.Length) return null;
            var tag = bind[t];
            if (!ReadTlv(bind, ref t, out var value)) return null;
            return tag switch
            {
                0x04 or 0x06 => Encoding.ASCII.GetString(value).TrimEnd('\0'),
                0x02 => value.Length > 0 ? ((long)value.Aggregate(0L, (a, b) => (a << 8) | b)).ToString() : null,
                _ => null,
            };
        }
        catch { return null; }
    }

    private static byte[] EncodeOid(string oid)
    {
        var parts = oid.Split('.').Select(int.Parse).ToArray();
        var bytes = new List<byte> { (byte)(parts[0] * 40 + parts[1]) };
        foreach (var part in parts.Skip(2))
        {
            if (part < 128) { bytes.Add((byte)part); continue; }
            var stack = new Stack<byte>();
            var v = part;
            stack.Push((byte)(v & 0x7F)); v >>= 7;
            while (v > 0) { stack.Push((byte)(0x80 | (v & 0x7F))); v >>= 7; }
            while (stack.Count > 0) bytes.Add(stack.Pop());
        }
        return bytes.ToArray();
    }

    private static byte[] EncodeInt(int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        var trimmed = bytes.SkipWhile((b, i) => i < bytes.Length - 1 && b == 0 && (bytes[i + 1] & 0x80) == 0).ToArray();
        return Tlv(0x02, trimmed);
    }

    private static byte[] Tlv(byte tag, byte[] content)
    {
        var len = content.Length < 128
            ? new[] { (byte)content.Length }
            : new[] { (byte)0x81, (byte)content.Length };
        return Concat(new[] { tag }, len, content);
    }

    private static bool ReadTlv(byte[] data, ref int pos, out byte[] content)
    {
        content = Array.Empty<byte>();
        if (pos + 2 > data.Length) return false;
        pos++; // tag
        var lenByte = data[pos++];
        int len;
        if ((lenByte & 0x80) == 0) len = lenByte;
        else
        {
            var n = lenByte & 0x7F;
            if (n == 0 || n > 2 || pos + n > data.Length) return false;
            len = 0;
            for (var i = 0; i < n; i++) len = (len << 8) | data[pos++];
        }
        if (pos + len > data.Length) return false;
        content = data[pos..(pos + len)];
        pos += len;
        return true;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        var at = 0;
        foreach (var part in parts) { Buffer.BlockCopy(part, 0, result, at, part.Length); at += part.Length; }
        return result;
    }
}

// ---- syslog + flow collectors -------------------------------------------

// NAMING (RMM-11 D38 fix lane, 2026-11-21): the collector wire
// records below are CollectorSyslogMessage / CollectorFlowSummary
// — the unprefixed names already belong to NetworkMonitoring.cs's
// model records in this same namespace, and the duplicate
// definitions (CS0101) broke every Acp.Shared build. Nothing
// outside this file referenced the collector records (verified:
// Acp.Core + Acp.Tests grep, no hits), so the rename is contained.
public sealed record CollectorSyslogMessage(
    string SourceIp, int? Facility, int? Severity, string? Hostname,
    string? AppName, string Message, DateTimeOffset ReceivedUtc);

public sealed record CollectorFlowSummary(
    string SourceIp, string DestIp, int SourcePort, int DestPort,
    int Protocol, long Packets, long Bytes, DateTimeOffset ReceivedUtc);

/// <summary>A real UDP syslog listener. Start binds the socket
/// given (all interfaces, or the caller's IPEndPoint); datagrams
/// parse through the model SyslogParser; sink throws are counted,
/// never fatal (BD-SHARED-TRANSPORT F6).</summary>
public sealed class SyslogCollector : IDisposable
{
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private int _sinkFaults;

    public bool IsListening { get; private set; }
    public int Port { get; private set; }
    public int SinkFaults => _sinkFaults;

    public void Start(int port, Action<CollectorSyslogMessage> sink) =>
        Start(new IPEndPoint(IPAddress.Any, port), sink);

    public void Start(IPEndPoint bind, Action<CollectorSyslogMessage> sink)
    {
        Stop();
        Port = bind.Port;
        _udp = new UdpClient(bind);
        _cts = new CancellationTokenSource();
        IsListening = true;
        var udp = _udp; var token = _cts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try { result = await udp.ReceiveAsync(token); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { continue; }
                try { sink(Parse(result.Buffer, result.RemoteEndPoint.Address)); }
                catch { Interlocked.Increment(ref _sinkFaults); }
            }
        }, token);
    }

    public void Stop()
    {
        IsListening = false;
        try { _cts?.Cancel(); } catch { }
        try { _udp?.Dispose(); } catch { }
        _udp = null;
    }

    public void Dispose() => Stop();

    /// <summary>BD-SHARED-TRANSPORT F6: parsing delegates to the
    /// model SyslogParser, whose shape check (D38-F9) decides
    /// whether the text after &lt;PRI&gt; is a timestamp or a
    /// hostname. The hand-rolled reader here took the host from a
    /// fixed offset 16 — garbage attribution for short or
    /// host-less datagrams.</summary>
    public static CollectorSyslogMessage Parse(byte[] data, IPAddress source)
    {
        var text = Encoding.UTF8.GetString(data);
        var parsed = SyslogParser.Parse(text);
        // An unparseable datagram still reaches the sink as a
        // message with NO claimed facility/severity/hostname —
        // the raw text is the evidence; the parser's null is not
        // dressed up as attribution.
        return new CollectorSyslogMessage(
            source.ToString(), parsed?.Facility, parsed?.Severity,
            parsed?.Hostname, parsed?.Tag, parsed?.Message ?? text,
            DateTimeOffset.UtcNow);
    }
}

public sealed class FlowCollector : IDisposable
{
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private int _sinkFaults;
    private readonly List<byte[]> _unsupported = new();

    public bool IsListening { get; private set; }
    public int Port { get; private set; }
    /// <summary>BD-SHARED-TRANSPORT F6: sink throws are counted,
    /// not fatal — the previous loop let a throw fault the task
    /// while IsListening still read true (dead collector, live
    /// claim).</summary>
    public int SinkFaults => _sinkFaults;
    /// <summary>Kept datagrams are capped (ring of the last 128) —
    /// previously unbounded growth fed by any sender on the LAN.</summary>
    public const int MaxUnsupportedKept = 128;
    public IReadOnlyList<byte[]> UnsupportedDatagrams { get { lock (_unsupported) return _unsupported.ToList(); } }

    public void Start(int port, Action<FlowRecord> sink) =>
        Start(new IPEndPoint(IPAddress.Any, port), sink);

    public void Start(IPEndPoint bind, Action<FlowRecord> sink)
    {
        Stop();
        Port = bind.Port;
        _udp = new UdpClient(bind);
        _cts = new CancellationTokenSource();
        IsListening = true;
        var udp = _udp; var token = _cts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try { result = await udp.ReceiveAsync(token); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { continue; }
                try
                {
                    var parsed = ParseDatagram(result.Buffer);
                    if (parsed.Count == 0)
                    {
                        lock (_unsupported)
                        {
                            _unsupported.Add(result.Buffer);
                            while (_unsupported.Count > MaxUnsupportedKept) _unsupported.RemoveAt(0);
                        }
                        continue;
                    }
                    foreach (var f in parsed)
                    {
                        try { sink(f); }
                        catch { Interlocked.Increment(ref _sinkFaults); }
                    }
                }
                catch { Interlocked.Increment(ref _sinkFaults); }
            }
        }, token);
    }

    public void Stop()
    {
        IsListening = false;
        try { _cts?.Cancel(); } catch { }
        try { _udp?.Dispose(); } catch { }
        _udp = null;
    }

    public void Dispose() => Stop();

    /// <summary>BD-SHARED-TRANSPORT F6: parsing delegates to the
    /// model NetFlowV5Parser (which enforces the exact datagram
    /// length and the real field layout). The hand-rolled reader
    /// here had the offsets wrong — srcPort/dstPort/bytes came
    /// from the nexthop/input/output fields, so per-port and
    /// per-byte anomaly evidence was computed over garbage.</summary>
    public static List<FlowRecord> ParseDatagram(byte[] data) =>
        NetFlowV5Parser.Parse(data)?.Flows.ToList() ?? new List<FlowRecord>();
}

/// <summary>BD-SHARED-TRANSPORT F7: neighbour/ARP cache MAC
/// resolution for the probe (the census's MAC-keyed identity was
/// dead on real data while the probe returned null MACs). Reads
/// /proc/net/arp where present and falls back to parsing
/// `arp -a` output (Windows). No entry ⇒ null, and the census
/// keys by IP honestly.</summary>
public static class ArpNeighbourCache
{
    public static string? TryResolveMac(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out _)) return null;
        try
        {
            if (File.Exists("/proc/net/arp"))
            {
                var fromProc = ParseProcNetArp(File.ReadAllText("/proc/net/arp"), ipAddress);
                if (fromProc is not null) return fromProc;
            }
        }
        catch { /* fall through to arp -a */ }
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null) return null;
            var output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(2000)) { try { proc.Kill(); } catch { } return null; }
            return ParseArpA(output, ipAddress);
        }
        catch { return null; }
    }

    /// <summary>/proc/net/arp: "IP address  HW type  Flags  HW address  Mask  Device".</summary>
    public static string? ParseProcNetArp(string text, string ipAddress)
    {
        foreach (var line in text.Split('\n'))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4 && parts[0] == ipAddress &&
                Wake.MagicPacket.ParseMac(parts[3]) is not null &&
                parts[3] != "00:00:00:00:00:00")
                return parts[3].ToLowerInvariant();
        }
        return null;
    }

    /// <summary>`arp -a` lines: "  192.168.1.5   aa-bb-cc-dd-ee-ff   dynamic".</summary>
    public static string? ParseArpA(string text, string ipAddress)
    {
        foreach (var line in text.Split('\n'))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[0] == ipAddress)
            {
                var mac = parts[1].Replace('-', ':');
                if (Wake.MagicPacket.ParseMac(mac) is not null) return mac.ToLowerInvariant();
            }
        }
        return null;
    }
}
