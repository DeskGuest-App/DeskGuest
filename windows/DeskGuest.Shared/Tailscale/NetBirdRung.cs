using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Transport;

namespace DeskGuest.Shared.Tailscale;

// =====================================================================
// FR-132 — the `netbird` rung: the second borrowed-mesh account
// rung, NetBird beside Tailscale's `mesh` (transports law:
// borrowed meshes ride the USER'S OWN provider account,
// operator-side only, never on endpoints, never required; D28 —
// the one provider sign-in happens on the provider's own page and
// DeskGuest never sees or types it).
//
// Same discipline as `mesh`, minus the D4 setup gate (that gate is
// Tailscale-specific law): the rung connects only when the
// owner's own NetBird client is installed AND connected, probed
// live on every connect; the target must sit in the mesh address
// ranges and, when the client reports its peer set, must be a
// KNOWN peer (the 100.64/10 block is shared with ISP CGNAT — the
// mesh F10 lesson applies verbatim). Admission is DeskGuest's: the
// LanProtocol v2 enrollment handshake runs over the connection
// exactly as on every rung — being on someone's NetBird network
// grants no DeskGuest session by itself.
//
// Exercising this rung end-to-end needs a NetBird account (the
// owner's own); the rung ships behind the probe seam so its
// refusals, gates and handshake are pinned without one.
// =====================================================================

public enum NetBirdReadiness { Ready, NotInstalled, NotConnected }

/// <summary>One probe of the owner's NetBird client.
/// KnownPeerAddresses is null when the client did not report a
/// peer set (the range gate alone then applies, as `mesh` does
/// without its peer feed).</summary>
public sealed record NetBirdProbeResult(
    NetBirdReadiness State,
    IReadOnlyList<string> SelfAddresses,
    IReadOnlyList<string>? KnownPeerAddresses,
    string Detail);

public interface INetBirdProbe
{
    NetBirdProbeResult Probe();
}

/// <summary>The production probe: finds the owner's `netbird`
/// client (PATH, then the standard Windows install path) and reads
/// `netbird status --json`. The document is walked tolerantly —
/// any string under an *ip*-named property is an address
/// candidate, any "status": "Connected" pair is the connection
/// signal — so client-version field drift degrades to
/// NotConnected (an honest refusal), never to a false Ready.</summary>
public sealed class NetBirdCliProbe : INetBirdProbe
{
    public NetBirdProbeResult Probe()
    {
        var exe = FindClient();
        if (exe is null)
            return new NetBirdProbeResult(NetBirdReadiness.NotInstalled, Array.Empty<string>(), null,
                "no netbird client found on this device (PATH or the standard install path)");
        string json;
        try
        {
            using var p = new Process();
            p.StartInfo = new ProcessStartInfo(exe, "status --json")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            p.Start();
            var read = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(10_000)) { try { p.Kill(entireProcessTree: true); } catch { } return NotConnected("netbird status did not answer within 10s"); }
            if (p.ExitCode != 0) return NotConnected($"netbird status exited {p.ExitCode}");
            json = read.GetAwaiter().GetResult();
        }
        catch (Exception ex) { return NotConnected($"netbird status could not run ({ex.GetType().Name})"); }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var addresses = new List<string>();
            var connected = false;
            Walk(doc.RootElement, null);
            void Walk(JsonElement el, string? prop)
            {
                switch (el.ValueKind)
                {
                    case JsonValueKind.Object:
                        foreach (var child in el.EnumerateObject()) Walk(child.Value, child.Name);
                        break;
                    case JsonValueKind.Array:
                        foreach (var child in el.EnumerateArray()) Walk(child, prop);
                        break;
                    case JsonValueKind.String:
                        var s = el.GetString();
                        if (s is null) break;
                        if (prop is not null && prop.Contains("ip", StringComparison.OrdinalIgnoreCase)
                            && IPAddress.TryParse(s.Split('/')[0], out var ip) && MeshAddress.IsTailnetAddress(ip.ToString()))
                            addresses.Add(ip.ToString());
                        if (string.Equals(prop, "status", StringComparison.OrdinalIgnoreCase)
                            && string.Equals(s, "Connected", StringComparison.OrdinalIgnoreCase))
                            connected = true;
                        break;
                }
            }
            if (!connected || addresses.Count == 0)
                return NotConnected(connected ? "client reports Connected but no mesh address was readable from its status"
                                              : "client is installed but not connected");
            var distinct = addresses.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            return new NetBirdProbeResult(NetBirdReadiness.Ready, distinct, distinct,
                "owner's NetBird client connected");
        }
        catch { return NotConnected("netbird status output was not readable JSON"); }

        static NetBirdProbeResult NotConnected(string detail) =>
            new(NetBirdReadiness.NotConnected, Array.Empty<string>(), null, detail);
    }

    private static string? FindClient()
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        var names = OperatingSystem.IsWindows() ? new[] { "netbird.exe", "netbird" } : new[] { "netbird" };
        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            foreach (var name in names)
            {
                var candidate = Path.Combine(dir.Trim(), name);
                if (File.Exists(candidate)) return candidate;
            }
        }
        if (OperatingSystem.IsWindows())
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var installed = Path.Combine(pf, "NetBird", "netbird.exe");
            if (File.Exists(installed)) return installed;
        }
        return null;
    }
}

/// <summary>The `netbird` rung. See the file header for the law
/// it implements; the shape mirrors MeshRung deliberately.</summary>
public sealed class NetBirdRung : IAuthenticatedRung
{
    private readonly Func<NetBirdProbeResult> _probe;
    private readonly Func<string, bool> _isMeshAddress;
    private readonly EnrollmentService? _enrollments;

    public NetBirdRung(EnrollmentService? enrollments = null)
        : this(new NetBirdCliProbe(), enrollments) { }

    /// <param name="isMeshAddress">The mesh-range gate; defaults
    /// to the production ranges. The seam exists for socket tests
    /// on loopback, exactly as MeshRung's — the gate's production
    /// shape is pinned separately.</param>
    public NetBirdRung(INetBirdProbe probe, EnrollmentService? enrollments = null,
        Func<string, bool>? isMeshAddress = null)
    { _probe = probe.Probe; _enrollments = enrollments; _isMeshAddress = isMeshAddress ?? MeshAddress.IsTailnetAddress; }

    public NetBirdRung(Func<NetBirdProbeResult> probe, EnrollmentService? enrollments = null,
        Func<string, bool>? isMeshAddress = null)
    { _probe = probe; _enrollments = enrollments; _isMeshAddress = isMeshAddress ?? MeshAddress.IsTailnetAddress; }

    public string Id => "netbird";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, null, ct);

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, identity, ct);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, DeviceIdentity? identity, CancellationToken ct)
    {
        ConnectAttempts++;
        NetBirdProbeResult probe;
        try { probe = _probe(); }
        catch (Exception ex) { return new TransportConnectResult(false, $"netbird: the NetBird client probe failed ({ex.GetType().Name}) — rung refused"); }
        if (probe.State == NetBirdReadiness.NotInstalled)
            return new TransportConnectResult(false,
                "netbird: NetBird is not installed on this device — this rung rides YOUR OWN NetBird account and client (operator-side only, never required); install NetBird and sign in on NetBird's own page (DeskGuest never sees that sign-in), or use another connection type");
        if (probe.State != NetBirdReadiness.Ready)
            return new TransportConnectResult(false,
                $"netbird: your NetBird client is installed but not connected ({probe.Detail}) — connect it under your own account and retry");
        if (string.IsNullOrWhiteSpace(target.Address))
            return new TransportConnectResult(false, "netbird: no NetBird address for this device");
        var (host, port) = LanRung.ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"netbird: bad address '{target.Address}'");
        if (!_isMeshAddress(host))
            return new TransportConnectResult(false,
                $"netbird: '{host}' is not a mesh-range (100.64.0.0/10 / mesh ULA) address — the netbird rung rides your NetBird network only");
        if (probe.KnownPeerAddresses is { } peers && !MeshAddress.IsKnownTailnetPeer(host, peers))
            return new TransportConnectResult(false,
                $"netbird: '{host}' is inside the mesh range but is NOT a peer in your NetBird client's reported peer set (the range is shared with ISP carrier-grade NAT) — refused");
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(host, port, timeout.Token);
            var stream = client.GetStream();
            if (identity is not null)
            {
                var (ok, detail, channel) = await RungHandshake.RunAsync("netbird", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail + " (NetBird network membership is not DeskGuest admission)"); }
                return new TransportConnectResult(true,
                    $"netbird: connected over your NetBird network to {host}:{port}", new RungStreamOwner(client, channel));
            }
            return new TransportConnectResult(true,
                $"netbird: connected over your NetBird network to {host}:{port}", new RungStreamOwner(client, stream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"netbird: {ex.GetType().Name}");
        }
    }
}
