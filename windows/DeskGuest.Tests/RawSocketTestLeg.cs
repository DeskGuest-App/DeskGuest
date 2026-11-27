using System.Net;
using System.Net.Sockets;

namespace DeskGuest.Tests;

/// <summary>CONV-F3 test transport (record: builds/rmm-r-logs/
/// log-conv-f3.md; precedent: the RMM-13 listener-fix lane,
/// log-rmm13-listener-fix.md). In THIS sandbox, .NET TcpClient and
/// HttpClient loopback connects are steered into the egress CONNECT
/// proxy, which answers with a plain-text refusal instead of
/// connecting — the connection never reaches the listener (proven
/// per-test by the CONV-F3 probe: listener accepts stay 0 on the
/// TcpClient/HttpClient legs, while a raw Socket leg arrives and
/// the real LanProtocol handshake succeeds over it). Tests whose
/// CLIENT leg is theirs to choose therefore connect with a raw
/// Socket here: the wire protocol, handshakes, refusal expectations
/// and session assertions are exercised verbatim — only the client
/// transport differs from production, where TcpClient/HttpClient
/// are unremarkable. Tests whose client leg lives INSIDE product
/// code (a rung's own TcpClient, the Core's IPC-driven start) are
/// NOT rerouted through this helper; they are reported
/// remaining-environmental in log-conv-f3-greenup.md rather than
/// re-implemented in the test.</summary>
internal static class RawSocketTestLeg
{
    /// <summary>Connect a raw socket to a loopback listener and
    /// return its stream (the stream owns the socket).</summary>
    public static async Task<NetworkStream> ConnectLoopbackAsync(int port)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(IPAddress.Loopback, port);
        return new NetworkStream(socket, ownsSocket: true);
    }

    /// <summary>Connect a raw socket to a loopback listener,
    /// returning the socket itself (TLS legs wrap it themselves).</summary>
    public static async Task<Socket> ConnectSocketLoopbackAsync(int port)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(IPAddress.Loopback, port);
        return socket;
    }

    /// <summary>Poll a host-side counter until it reaches the
    /// expected state. Listener counters increment on the host's
    /// handler task AFTER the verdict line is written, so a client
    /// that has just read its verdict can legitimately observe the
    /// counter a moment early; the rung-driven form of these tests
    /// had the same property. Polling waits for the host's recorded
    /// outcome — it never manufactures it.</summary>
    public static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (!condition() && Environment.TickCount64 < deadline)
            await Task.Delay(25);
    }
}
