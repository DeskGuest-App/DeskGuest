using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DeskGuest.Shared.Connection;

namespace DeskGuest.Core.Platform;

/// <summary>
/// Real lane probe: Tailscale lane = an address in 100.64.0.0/10 (the
/// tailnet CGNAT range); LAN lane = a private RFC1918 address outside
/// the tailnet range. Loopback is never a lane (DESIGN §6.1: the
/// listener binds the tailnet and LAN addresses, never 0.0.0.0).
/// </summary>
public sealed class NetworkProbe : ILaneAddressProbe
{
    public string? ProbeAddress(LaneKind lane)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var ip = ua.Address;
                if (IPAddress.IsLoopback(ip)) continue;
                var b = ip.GetAddressBytes();
                var isTailnet = b[0] == 100 && (b[1] & 0xC0) == 0x40; // 100.64.0.0/10
                var isPrivate = b[0] == 10 || (b[1] >= 16 && b[1] <= 31 && b[0] == 172) || (b[0] == 192 && b[1] == 168);
                if (lane == LaneKind.Tailscale && isTailnet) return ip.ToString();
                if (lane == LaneKind.Lan && isPrivate && !isTailnet) return ip.ToString();
            }
        }
        return null;
    }
}

/// <summary>Test/dev probe with scripted addresses.</summary>
public sealed class FakeLaneProbe : ILaneAddressProbe
{
    private readonly Dictionary<LaneKind, string?> _addresses = new();
    public void Set(LaneKind lane, string? address) => _addresses[lane] = address;
    public string? ProbeAddress(LaneKind lane) => _addresses.GetValueOrDefault(lane);
}
