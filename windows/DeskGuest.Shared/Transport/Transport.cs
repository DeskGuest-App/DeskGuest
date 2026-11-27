using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Shared.Transport;

/// <summary>Where a rung should try to reach a device. Address is a
/// host or host:port string — from discovery, or entered by hand
/// (connect-by-address, D19: the fallback when discovery cannot see
/// across segments; it rides the `lan` rung's semantics).</summary>
public sealed record TransportTarget(string DeviceId, string? Address = null);

/// <summary>One connection attempt's outcome. On success Stream is
/// the live, authenticated session channel (caller owns it).</summary>
public sealed record TransportConnectResult(bool Ok, string Detail, Stream? Stream = null);

/// <summary>A transport rung (D29/D32). Rungs are DORMANT by
/// discipline: registering a rung opens no listener and sends no
/// traffic — only an explicit ConnectAsync from the failover engine
/// makes a rung speak. The engine is rung-agnostic: hub / mesh /
/// ipv6 / ownpath / tor plug in behind this interface without
/// engine changes.</summary>
public interface ITransportRung
{
    string Id { get; }
    /// <summary>True until this rung has carried any traffic.</summary>
    bool IsDormant { get; }
    int ConnectAttempts { get; }
    Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default);
}

/// <summary>The DeskGuest session protocol over a direct socket (the
/// `lan` rung), v2 (BD-SHARED-TRANSPORT F1 fix). The v1 handshake
/// was one-way and relayable: only the client signed, the signature
/// covered only Domain|deviceId|nonce, and the stream afterwards
/// was plaintext TCP — a spoofed host could relay a real host's
/// challenge, harvest the client's signature, and replay it to the
/// real host, and every rung's traffic could be read/hijacked.
/// V2 is mutually authenticated and encrypted:
///  1. Host → CHAL2: host nonce, host DeviceId, host ephemeral
///     X25519 key, and the host's Ed25519 signature over all three.
///     The client verifies it against the host's ENROLLED key and
///     the expected host DeviceId before signing anything — a
///     relayed challenge from a different host fails here.
///  2. Client → HELLO2: client nonce, client ephemeral key, and
///     the client's signature over the FULL transcript (both ids,
///     both nonces, both ephemeral keys) — the proof is bound to
///     this channel and this host, so it cannot be relayed to a
///     different host or a different connection.
///  3. Host → OK2: the host's signature over the transcript hash.
///  4. Both sides derive per-direction AES-256-GCM keys via HKDF
///     from the X25519 shared secret + transcript hash; all later
///     traffic travels in AEAD frames (see LanSecureChannel).
/// There is no unauthenticated or plaintext mode: a peer that
/// cannot sign for an enrolled, unrevoked DeviceId is refused.</summary>
public static class LanProtocol
{
    public const string Domain = "deskguest-transport-v1";
    public const string DomainV2 = "deskguest-transport-v2";
    public const int DefaultPort = 47621;
    public const int MaxLineBytes = 8192;

    /// <summary>Legacy v1 proof message — retained ONLY so the
    /// pre-v2 manual-wire tests can be read against history. No
    /// product code signs or verifies it any more.</summary>
    public static byte[] ProofMessage(string deviceId, string nonceBase64) =>
        Encoding.UTF8.GetBytes($"{Domain}|{deviceId}|{nonceBase64}");

    public static byte[] HostProofMessage(string hostDeviceId, string hostNonceBase64, string hostEphemeralBase64) =>
        Encoding.UTF8.GetBytes($"{DomainV2}|host|{hostDeviceId}|{hostNonceBase64}|{hostEphemeralBase64}");

    public static byte[] ClientProofMessage(string clientDeviceId, string hostDeviceId,
        string hostNonceBase64, string clientNonceBase64, string hostEphemeralBase64, string clientEphemeralBase64) =>
        Encoding.UTF8.GetBytes($"{DomainV2}|client|{clientDeviceId}|{hostDeviceId}|{hostNonceBase64}|{clientNonceBase64}|{hostEphemeralBase64}|{clientEphemeralBase64}");

    public static byte[] ConfirmMessage(string transcriptHashHex) =>
        Encoding.UTF8.GetBytes($"{DomainV2}|confirm|{transcriptHashHex}");

    /// <summary>W14 P3-F14b (W13-P3-F14b spec): the reply for one
    /// post-handshake session-protocol line on the host listener.
    /// The STOPLOCAL wire verb is REMOVED — a channel peer holds no
    /// local-stop verb at all (the on-device local STOP, through
    /// the endpoint's own UI/session layer, is not a wire verb and
    /// is unchanged). A peer that sends it is refused BY NAME
    /// ("REFUSED stoplocal_removed"), nothing is stopped, and the
    /// channel stays open. A SESSION line whose initiator fails
    /// the W14 P3-F2 owner binding is likewise refused by name
    /// ("REFUSED owner_mismatch") before the generic unknown-verb
    /// answer; every other line keeps its pre-W14 reply, so an
    /// owner-clean SESSION still meets the listener's existing
    /// posture (this listener serves no SESSION verb).</summary>
    /// <param name="sessionOwnerRefusal">The P3-F2 refusal reason
    /// for a SESSION line (see EnrollmentService.SessionOwnerRefusal),
    /// or null when the line is not a SESSION line or the binding
    /// passes.</param>
    public static string SessionLineReply(string? line, string? sessionOwnerRefusal = null)
    {
        if (line == "PING") return "PONG";
        if (line == "STOPLOCAL") return "REFUSED stoplocal_removed";
        if (line is not null && line.StartsWith("SESSION ", StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(sessionOwnerRefusal))
            return "REFUSED " + sessionOwnerRefusal;
        return "ERR unknown";
    }

    /// <summary>The SESSION verb's initiator field (field 2 of
    /// "SESSION &lt;scopeId&gt; &lt;initiator&gt; &lt;hostUser&gt;
    /// &lt;kind&gt; [recording]"), or null when the line is not a
    /// well-formed SESSION line. Used by the host listener to run
    /// the P3-F2 owner binding against the handshake-proven peer.</summary>
    public static string? SessionInitiatorOf(string? line)
    {
        if (line is null || !line.StartsWith("SESSION ", StringComparison.Ordinal)) return null;
        var parts = line.Split(' ');
        return parts.Length >= 5 ? parts[2] : null;
    }

    public static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new List<byte>();
        var one = new byte[1];
        while (buffer.Count <= MaxLineBytes)
        {
            var n = await stream.ReadAsync(one, 0, 1, ct);
            if (n == 0) return buffer.Count == 0 ? null : Encoding.UTF8.GetString(buffer.ToArray());
            if (one[0] == (byte)'\n') return Encoding.UTF8.GetString(buffer.ToArray()).TrimEnd('\r');
            buffer.Add(one[0]);
        }
        return null; // over-long line: fail closed
    }

    public static async Task WriteLineAsync(Stream stream, string line, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        await stream.WriteAsync(bytes, 0, bytes.Length, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Why a client handshake ended (CONV-F3 diagnostic
    /// honesty): a peer that never issued an DeskGuest challenge — wrong
    /// service, garbage peer, or a connection that never reached
    /// the host — is NOT a host refusing our proof, and the rungs'
    /// failure details must not say it is. Only a peer that spoke
    /// the protocol (valid CHAL2) and then declined our HELLO2
    /// earns the refusal wording.</summary>
    public enum ClientHandshakeOutcome
    {
        Connected,
        /// <summary>The host spoke DeskGuest and refused our proof of possession.</summary>
        HostRefused,
        /// <summary>No DeskGuest challenge was ever received: the peer did not speak the protocol.</summary>
        NoChallengeReceived,
        /// <summary>The peer claimed to be a host but could not prove
        /// it (wrong DeviceId, unknown/revoked enrollment, or a bad
        /// signature) — a spoofed or relaying host lands here and
        /// the client signs NOTHING for it.</summary>
        HostAuthenticationFailed,
    }

    /// <summary>The outcome of a v2 client handshake: on success,
    /// Channel is the AEAD session channel (caller owns it).</summary>
    public sealed record ClientHandshakeResult(ClientHandshakeOutcome Outcome, Stream? Channel);

    /// <summary>Client half of v2: verify the host FIRST (enrolled
    /// key + expected DeviceId), then sign the full transcript and
    /// derive the AEAD channel. The client never signs for a host
    /// it has not authenticated — the v1 relay is dead by
    /// construction.</summary>
    public static async Task<ClientHandshakeResult> ClientHandshakeDetailedAsync(
        Stream stream, DeviceIdentity identity, EnrollmentService enrollments,
        string? expectedHostDeviceId, CancellationToken ct)
    {
        var challenge = await ReadLineAsync(stream, ct);
        if (challenge is null || !challenge.StartsWith("CHAL2 ", StringComparison.Ordinal))
            return new ClientHandshakeResult(ClientHandshakeOutcome.NoChallengeReceived, null);
        var parts = challenge.Split(' ');
        if (parts.Length != 5) return new ClientHandshakeResult(ClientHandshakeOutcome.NoChallengeReceived, null);
        var hostNonce = parts[1]; var hostDeviceId = parts[2]; var hostEphB64 = parts[3]; var hostSigB64 = parts[4];
        if (hostNonce.Length < 16 || hostNonce.Length > 128)
            return new ClientHandshakeResult(ClientHandshakeOutcome.NoChallengeReceived, null);
        if (!string.IsNullOrWhiteSpace(expectedHostDeviceId) &&
            !string.Equals(expectedHostDeviceId, hostDeviceId, StringComparison.OrdinalIgnoreCase))
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null);
        byte[] hostEph;
        try { hostEph = Convert.FromBase64String(hostEphB64); }
        catch { return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null); }
        if (hostEph.Length != 32)
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null);
        // VerifyEnrolledSignature refuses unknown AND revoked keys.
        if (!enrollments.VerifyEnrolledSignature(hostDeviceId,
                HostProofMessage(hostDeviceId, hostNonce, hostEphB64), hostSigB64))
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null);

        var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var clientEphScalar = RandomNumberGenerator.GetBytes(32);
        var clientEph = X25519.Raw(clientEphScalar, X25519.BasePointU);
        var clientEphB64 = Convert.ToBase64String(clientEph);
        var clientSig = identity.Sign(ClientProofMessage(
            identity.DeviceId, hostDeviceId, hostNonce, clientNonce, hostEphB64, clientEphB64));
        await WriteLineAsync(stream,
            $"HELLO2 {identity.DeviceId} {clientNonce} {clientEphB64} {Convert.ToBase64String(clientSig)}", ct);
        var verdict = await ReadLineAsync(stream, ct);
        if (verdict is null || !verdict.StartsWith("OK2 ", StringComparison.Ordinal))
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostRefused, null);
        var transcript = TranscriptHash(hostDeviceId, hostNonce, hostEphB64,
            identity.DeviceId, clientNonce, clientEphB64);
        if (!enrollments.VerifyEnrolledSignature(hostDeviceId, ConfirmMessage(transcript), verdict[4..].Trim()))
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null);
        var channel = DeriveChannel(stream, clientEphScalar, hostEph, transcript, isHost: false);
        if (channel is null)
            return new ClientHandshakeResult(ClientHandshakeOutcome.HostAuthenticationFailed, null);
        return new ClientHandshakeResult(ClientHandshakeOutcome.Connected, channel);
    }

    /// <summary>Bool convenience over the detailed client
    /// handshake. NOTE: on success the AEAD channel is DISCARDED —
    /// callers that will speak the session protocol must use
    /// ClientHandshakeDetailedAsync and keep the channel.</summary>
    public static async Task<bool> ClientHandshakeAsync(
        Stream stream, DeviceIdentity identity, EnrollmentService enrollments,
        string? expectedHostDeviceId, CancellationToken ct)
    {
        var result = await ClientHandshakeDetailedAsync(stream, identity, enrollments, expectedHostDeviceId, ct);
        if (result.Outcome != ClientHandshakeOutcome.Connected) { result.Channel?.Dispose(); return false; }
        result.Channel?.Dispose();
        return true;
    }

    /// <summary>Host half of v2: prove OUR identity first (the
    /// host signs its challenge with its own enrolled device key),
    /// then verify the client's transcript-bound proof against the
    /// enrolled key. Returns the proven DeviceId and the AEAD
    /// channel, or (null, null) — unauthenticated, unknown,
    /// revoked, spoofed and relaying peers all land there.</summary>
    public static async Task<(string? DeviceId, Stream? Channel)> HostHandshakeAsync(
        Stream stream, EnrollmentService enrollments, DeviceIdentity hostIdentity, CancellationToken ct)
    {
        var hostNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var hostEphScalar = RandomNumberGenerator.GetBytes(32);
        var hostEph = X25519.Raw(hostEphScalar, X25519.BasePointU);
        var hostEphB64 = Convert.ToBase64String(hostEph);
        var hostSig = hostIdentity.Sign(HostProofMessage(hostIdentity.DeviceId, hostNonce, hostEphB64));
        await WriteLineAsync(stream,
            $"CHAL2 {hostNonce} {hostIdentity.DeviceId} {hostEphB64} {Convert.ToBase64String(hostSig)}", ct);
        var hello = await ReadLineAsync(stream, ct);
        if (hello is null) return (null, null);
        var parts = hello.Split(' ');
        if (parts.Length != 5 || parts[0] != "HELLO2") { await TryRefuse(stream, ct); return (null, null); }
        var deviceId = parts[1]; var clientNonce = parts[2]; var clientEphB64 = parts[3]; var clientSigB64 = parts[4];
        byte[] clientEph;
        try { clientEph = Convert.FromBase64String(clientEphB64); }
        catch { await TryRefuse(stream, ct); return (null, null); }
        if (clientEph.Length != 32) { await TryRefuse(stream, ct); return (null, null); }
        if (!enrollments.VerifyEnrolledSignature(deviceId,
                ClientProofMessage(deviceId, hostIdentity.DeviceId, hostNonce, clientNonce, hostEphB64, clientEphB64),
                clientSigB64))
        { await TryRefuse(stream, ct); return (null, null); }
        var transcript = TranscriptHash(hostIdentity.DeviceId, hostNonce, hostEphB64,
            deviceId, clientNonce, clientEphB64);
        var confirmSig = hostIdentity.Sign(ConfirmMessage(transcript));
        var channel = DeriveChannel(stream, hostEphScalar, clientEph, transcript, isHost: true);
        if (channel is null) { await TryRefuse(stream, ct); return (null, null); }
        await WriteLineAsync(stream, $"OK2 {Convert.ToBase64String(confirmSig)}", ct);
        var device = enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
        return (device?.DeviceId ?? deviceId, channel);
    }

    private static string TranscriptHash(string hostDeviceId, string hostNonce, string hostEphB64,
        string clientDeviceId, string clientNonce, string clientEphB64) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{DomainV2}|transcript|{hostDeviceId}|{hostNonce}|{hostEphB64}|{clientDeviceId}|{clientNonce}|{clientEphB64}")))
            .ToLowerInvariant();

    private static LanSecureChannel? DeriveChannel(Stream inner, byte[] ownEphScalar, byte[] peerEph,
        string transcriptHashHex, bool isHost)
    {
        var shared = X25519.Raw(ownEphScalar, peerEph);
        if (shared.All(b => b == 0)) return null; // contributory-behaviour check: refuse a null shared secret
        var salt = Convert.FromHexString(transcriptHashHex);
        var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 64, salt,
            Encoding.UTF8.GetBytes($"{DomainV2}|session-keys"));
        CryptographicOperations.ZeroMemory(shared);
        return new LanSecureChannel(inner,
            sendKey: isHost ? okm[32..] : okm[..32],
            receiveKey: isHost ? okm[..32] : okm[32..]);
    }

    private static async Task TryRefuse(Stream stream, CancellationToken ct)
    {
        try { await WriteLineAsync(stream, "REFUSE", ct); } catch { /* peer already gone */ }
    }
}

/// <summary>The AEAD session channel (BD-SHARED-TRANSPORT F1):
/// AES-256-GCM frames over the raw stream. Wire shape per frame:
/// [4-byte big-endian ciphertext length][12-byte nonce][ciphertext
/// + 16-byte tag]. Nonces are counter-based per direction (never
/// reused under a direction key); each frame's AAD is its own
/// sequence number, so reordered, replayed or truncated frames
/// fail authentication and kill the channel. Writes are buffered
/// until Flush (one frame per flush, chunked at 64 KiB); reads
/// serve decrypted plaintext from the current frame.</summary>
public sealed class LanSecureChannel : Stream
{
    private const int MaxFramePlaintext = 64 * 1024;
    private readonly Stream _inner;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private long _sendSeq;
    private long _receiveSeq;
    private readonly MemoryStream _writeBuffer = new();
    private byte[] _readPlain = Array.Empty<byte>();
    private int _readPos;
    private bool _dead;

    public LanSecureChannel(Stream inner, byte[] sendKey, byte[] receiveKey)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        if (sendKey.Length != 32 || receiveKey.Length != 32)
            throw new ArgumentException("LanSecureChannel keys are 32 bytes (AES-256).");
        _sendKey = sendKey.ToArray();
        _receiveKey = receiveKey.ToArray();
    }

    public override bool CanRead => !_dead;
    public override bool CanSeek => false;
    public override bool CanWrite => !_dead;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    private static byte[] NonceFor(long seq)
    {
        var nonce = new byte[12];
        BitConverter.GetBytes(seq).CopyTo(nonce, 4);
        return nonce;
    }

    private static byte[] AadFor(long seq) => Encoding.UTF8.GetBytes($"deskguest-transport-v2|frame|{seq}");

    public override void Flush() => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task FlushAsync(CancellationToken ct)
    {
        if (_dead) throw new IOException("secure channel is dead (authentication failure or close)");
        if (_writeBuffer.Length == 0) return;
        var plain = _writeBuffer.ToArray();
        _writeBuffer.SetLength(0);
        for (var at = 0; at < plain.Length; at += MaxFramePlaintext)
        {
            var chunk = plain[at..Math.Min(at + MaxFramePlaintext, plain.Length)];
            var seq = ++_sendSeq;
            var nonce = NonceFor(seq);
            var cipher = new byte[chunk.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(_sendKey, 16))
                aes.Encrypt(nonce, chunk, cipher, tag, AadFor(seq));
            var frame = new byte[4 + 12 + cipher.Length + 16];
            BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(cipher.Length + 16)).CopyTo(frame, 0);
            nonce.CopyTo(frame, 4);
            cipher.CopyTo(frame, 16);
            tag.CopyTo(frame, 16 + cipher.Length);
            await _inner.WriteAsync(frame, ct);
        }
        await _inner.FlushAsync(ct);
    }

    public override void Write(byte[] buffer, int offset, int count) => _writeBuffer.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    { _writeBuffer.Write(buffer.Span); return ValueTask.CompletedTask; }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    { _writeBuffer.Write(buffer, offset, count); return Task.CompletedTask; }

    // Returns false ONLY for a clean EOF exactly at a frame
    // boundary. Anything else — a partial frame, a bad length, a
    // nonce out of sequence, a tag that does not verify — is an
    // authentication failure and THROWS: a tampered frame must
    // never be indistinguishable from a polite close (a reader
    // that sees EOF stops; a reader that sees an authentication
    // failure alarms). The channel is dead from that point and
    // every later read throws the same way.
    private async Task<bool> FillAsync(CancellationToken ct)
    {
        var header = new byte[4];
        var headerRead = await ReadUpToAsync(header, ct);
        if (headerRead == 0) return false; // clean EOF at a frame boundary
        if (headerRead < header.Length) throw Dead("partial frame header — the channel is dead");
        var len = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(header, 0));
        if (len < 16 || len > MaxFramePlaintext + 16)
            throw Dead($"frame length {len} is impossible — the channel is dead");
        var rest = new byte[12 + len];
        if (await ReadUpToAsync(rest, ct) < rest.Length)
            throw Dead("frame truncated mid-body — the channel is dead");
        var seq = ++_receiveSeq;
        var nonce = rest[..12];
        if (!nonce.SequenceEqual(NonceFor(seq)))
            throw Dead("frame nonce out of sequence (replay or reorder) — the channel is dead");
        var cipher = rest[12..^16];
        var tag = rest[^16..];
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(_receiveKey, 16);
            aes.Decrypt(nonce, cipher, tag, plain, AadFor(seq));
        }
        catch (CryptographicException)
        {
            throw Dead("frame authentication tag did not verify — the channel is dead");
        }
        _readPlain = plain;
        _readPos = 0;
        return true;
    }

    private InvalidDataException Dead(string why)
    {
        _dead = true;
        return new InvalidDataException($"secure channel authentication failure: {why}");
    }

    private async Task<int> ReadUpToAsync(byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await _inner.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_dead) throw new InvalidDataException(
            "secure channel authentication failure: the channel is dead (an earlier frame failed verification)");
        if (_readPos >= _readPlain.Length && !await FillAsync(ct)) return 0;
        var n = Math.Min(buffer.Length, _readPlain.Length - _readPos);
        _readPlain.AsMemory(_readPos, n).CopyTo(buffer);
        _readPos += n;
        return n;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        await ReadAsync(buffer.AsMemory(offset, count), ct);

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(_sendKey);
            CryptographicOperations.ZeroMemory(_receiveKey);
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }
}

/// <summary>The `lan` rung: a direct TCP socket on the local
/// network carrying <see cref="LanProtocol"/>. Connect-by-address
/// is this same rung with a hand-entered address (D19).</summary>
public sealed class LanRung : IAuthenticatedRung
{
    private readonly EnrollmentService? _enrollments;

    /// <param name="enrollments">The enrollment store the v2
    /// handshake verifies the HOST against. A session connect
    /// without it refuses (fail closed): an unverifiable host is
    /// not a host. The bare reachability probe (ConnectAsync, no
    /// identity) does not need it.</param>
    public LanRung(EnrollmentService? enrollments = null) => _enrollments = enrollments;

    public string Id => "lan";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, ct);

    /// <summary>Connect-by-address (D19 clarification): a manually
    /// entered endpoint address, same rung, same authenticated
    /// protocol — the answer when discovery can't see the device.</summary>
    public async Task<TransportConnectResult> ConnectByAddressAsync(string address, string deviceId, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(new TransportTarget(deviceId, address), ct, identity);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, CancellationToken ct, DeviceIdentity? identity = null)
    {
        ConnectAttempts++;
        if (string.IsNullOrWhiteSpace(target.Address))
            return new TransportConnectResult(false, "lan: no address (not discovered, none entered)");
        var (host, port) = ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"lan: bad address '{target.Address}'");
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(host, port, timeout.Token);
            var stream = client.GetStream();
            // Without a local identity we can still prove the peer
            // answers the protocol — but a session requires the v2
            // mutual handshake when the caller supplies identity;
            // the engine path always supplies it via
            // ConnectSessionAsync. The returned stream is the AEAD
            // channel, never the raw socket.
            if (identity is not null)
            {
                if (_enrollments is null)
                {
                    client.Dispose();
                    return new TransportConnectResult(false,
                        "lan: no enrollment store wired on this rung — the host cannot be verified, session refused (fail closed)");
                }
                var hs = await LanProtocol.ClientHandshakeDetailedAsync(stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (hs.Outcome != LanProtocol.ClientHandshakeOutcome.Connected || hs.Channel is null)
                {
                    client.Dispose();
                    return new TransportConnectResult(false, hs.Outcome switch
                    {
                        LanProtocol.ClientHandshakeOutcome.HostRefused =>
                            "lan: host refused our proof of possession",
                        LanProtocol.ClientHandshakeOutcome.HostAuthenticationFailed =>
                            "lan: the peer could not prove it is the enrolled host — refused before signing anything",
                        _ => "lan: no DeskGuest challenge received — the peer did not speak the DeskGuest protocol",
                    });
                }
                return new TransportConnectResult(true, $"lan: connected to {host}:{port} (mutually authenticated, AEAD channel)", new TcpStreamOwner(client, hs.Channel));
            }
            return new TransportConnectResult(true, $"lan: connected to {host}:{port}", new TcpStreamOwner(client, stream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"lan: {ex.GetType().Name}");
        }
    }

    /// <summary>Engine entry: connect AND authenticate as
    /// <paramref name="identity"/> (the engine calls this, never the
    /// bare probe above, for a real session).</summary>
    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, ct, identity);

    /// <summary>Parse a rung address (BD-SHARED-TRANSPORT F10):
    /// bracketed IPv6 keeps its brackets OFF the host ("[::1]:47621"
    /// → host "::1"); an unbracketed value with more than one colon
    /// is a bare IPv6 literal and takes the default port — the old
    /// last-colon split turned "2600::1234" into host "2600:" port
    /// 1234. A single-colon value splits host:port as before.</summary>
    public static (string? Host, int Port) ParseAddress(string address)
    {
        var a = (address ?? "").Trim();
        if (a.Length == 0) return (null, 0);
        if (a.StartsWith('['))
        {
            var close = a.IndexOf(']');
            if (close < 2) return (null, 0);
            var host = a[1..close];
            if (close + 1 == a.Length) return (host, LanProtocol.DefaultPort);
            if (a[close + 1] == ':' && int.TryParse(a[(close + 2)..], out var bp))
                return bp is > 0 and <= 65535 ? (host, bp) : (null, 0);
            return (null, 0);
        }
        var first = a.IndexOf(':');
        if (first < 0) return (a, LanProtocol.DefaultPort);
        if (a.LastIndexOf(':') != first)
            return (a, LanProtocol.DefaultPort); // bare IPv6 literal, no port
        if (int.TryParse(a[(first + 1)..], out var port))
            return port is > 0 and <= 65535 ? (a[..first], port) : (null, 0);
        return (a, LanProtocol.DefaultPort);
    }

    internal sealed class TcpStreamOwner : Stream
    {
        private readonly TcpClient _client; private readonly Stream _inner;
        public TcpStreamOwner(TcpClient client, Stream inner) { _client = client; _inner = inner; }
        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _inner.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _inner.ReadAsync(buffer, offset, count, ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => _inner.WriteAsync(buffer, ct);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _inner.WriteAsync(buffer, offset, count, ct);
        protected override void Dispose(bool disposing) { if (disposing) { _inner.Dispose(); _client.Dispose(); } base.Dispose(disposing); }
    }
}

/// <summary>The host side of the `lan` rung. NOT listening until
/// Start is called — a configured-but-dormant rung has no listener
/// and no traffic (attack-surface discipline, D29). Each accepted
/// connection must pass the proof-of-possession handshake before
/// it can speak the session protocol (PING → PONG).</summary>
public sealed class LanHostListener : IDisposable
{
    private readonly EnrollmentService _enrollments;
    private readonly DeviceIdentity? _hostIdentity;
    private readonly SemaphoreSlim _handshakeCap = new(MaxConcurrentHandshakes, MaxConcurrentHandshakes);
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    public int Port { get; private set; }
    public bool IsListening => _listener is not null;
    public int AcceptedSessions { get; private set; }
    public int RefusedHandshakes { get; private set; }

    /// <summary>BD-SHARED-TRANSPORT F8: a peer that connects and
    /// never speaks holds a handshake slot for at most this long,
    /// and at most this many half-open handshakes run at once —
    /// the listener cannot be pinned by silent connections.</summary>
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    public const int MaxConcurrentHandshakes = 16;

    /// <param name="hostIdentity">This host's own device identity:
    /// v2 requires the host to PROVE itself before the client
    /// signs anything. A listener without one refuses every
    /// handshake (fail closed).</param>
    public LanHostListener(EnrollmentService enrollments, DeviceIdentity? hostIdentity = null)
    {
        _enrollments = enrollments;
        _hostIdentity = hostIdentity;
    }

    public void Start(IPAddress address, int port = LanProtocol.DefaultPort)
    {
        if (_listener is not null) return;
        _listener = new TcpListener(address, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _cts = new CancellationTokenSource();
        _ = AcceptLoopAsync(_cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct); }
            catch { return; }
            _ = HandleAsync(client, ct);
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try { await ServeConnectedStreamAsync(client.GetStream(), ct); }
            catch { /* a dead peer ends its channel, nothing more */ }
        }
    }

    /// <summary>Serve one already-connected stream: the v2 host
    /// handshake, then the session-protocol line loop — exactly
    /// what an accepted socket gets. The relay host connector
    /// (RelayHostConnector, FR-131) runs paired relay streams
    /// through this same routine: there is ONE host-side session
    /// protocol implementation, whatever road the bytes arrived
    /// by. Returns true when a session was accepted and served.</summary>
    public async Task<bool> ServeConnectedStreamAsync(Stream stream, CancellationToken ct)
    {
        if (_hostIdentity is null) { RefusedHandshakes++; return false; }
        if (!await _handshakeCap.WaitAsync(0))
        { RefusedHandshakes++; return false; } // half-open cap reached: drop at once
        try
        {
            string? deviceId; Stream? channel;
            try
            {
                using var hsTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                hsTimeout.CancelAfter(HandshakeTimeout);
                (deviceId, channel) = await LanProtocol.HostHandshakeAsync(
                    stream, _enrollments, _hostIdentity, hsTimeout.Token);
            }
            finally { _handshakeCap.Release(); } // the cap binds HALF-OPEN handshakes, not live sessions
            if (deviceId is null || channel is null) { RefusedHandshakes++; return false; }
            AcceptedSessions++;
            using (channel)
            {
                while (!ct.IsCancellationRequested)
                {
                    var line = await LanProtocol.ReadLineAsync(channel, ct);
                    if (line is null) return true;
                    // W14: STOPLOCAL is refused by name and the
                    // channel stays open (P3-F14b); a SESSION
                    // line runs the P3-F2 owner binding against
                    // the handshake-proven peer device id first.
                    var ownerRefusal = LanProtocol.SessionInitiatorOf(line) is { } initiator
                        ? _enrollments.SessionOwnerRefusal(deviceId, initiator)
                        : null;
                    await LanProtocol.WriteLineAsync(channel,
                        LanProtocol.SessionLineReply(line, ownerRefusal), ct);
                }
            }
            return true;
        }
        catch { return false; /* a dead peer ends its channel, nothing more */ }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _listener = null;
    }

    public void Dispose() => Stop();
}

/// <summary>A rung that does exactly what a test tells it to —
/// the engine's rung-agnosticism proof: the failover engine walks
/// this double exactly as it walks `lan`, with no engine change.</summary>
public sealed class StubRung : ITransportRung
{
    private readonly Func<TransportTarget, TransportConnectResult> _behavior;
    public StubRung(string id, Func<TransportTarget, TransportConnectResult> behavior)
    { Id = id; _behavior = behavior; }
    public string Id { get; }
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }
    public Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default)
    { ConnectAttempts++; return Task.FromResult(_behavior(target)); }
    public static StubRung Failing(string id) => new(id, _ => new TransportConnectResult(false, $"{id}: forced failure (test double)"));
    public static StubRung Succeeding(string id) => new(id, _ => new TransportConnectResult(true, $"{id}: connected (test double)", new MemoryStream()));
}

/// <summary>One failover-engine event. Session linkage lives here
/// AND in the Slice 3 event lists (end + new-start, named ids).</summary>
public sealed record TransportEvent(string Kind, string? Rung, string Detail, string? FromSessionId = null, string? ToSessionId = null);

/// <summary>The auto failover engine (D29/D32 unified model).
/// Start: resolve EffectiveTransports (group set ∩ company ceiling
/// ∩ per-device pin), walk in order, first rung that connects AND
/// passes the Slice 3 start gates carries the session — the record's
/// TransportRung is that rung. Manual mode: the caller pins to a
/// subset of the resolved set; the engine never attempts a rung
/// outside the pin, and a pin outside the set is refused outright.
/// Re-establish: when a live session's rung dies, the old session
/// ENDS (reason transport_failover) and a new session starts on the
/// next rung — linked by events, honestly a reconnect. Attempts are
/// bounded by the set size per operation: no reconnect loops.</summary>
public sealed class TransportSessionManager
{
    private readonly RosterService _roster;
    private readonly SessionService _sessions;
    private readonly Dictionary<string, ITransportRung> _rungs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, LiveLink> _live = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<TransportEvent> _events = new();
    private readonly DeviceIdentity? _identity;

    private sealed record LiveLink(string Rung, TransportTarget Target, string ScopeId, string HostDeviceId,
        string InitiatorUserId, string Kind, string Recording, Stream? Stream, IReadOnlyList<string> OrderedRungs);

    public TransportSessionManager(RosterService roster, SessionService sessions,
        IEnumerable<ITransportRung> rungs, DeviceIdentity? identity = null)
    {
        _roster = roster; _sessions = sessions; _identity = identity;
        foreach (var rung in rungs) _rungs[rung.Id] = rung;
    }

    public IReadOnlyList<TransportEvent> Events { get { lock (_events) return _events.ToList(); } }
    public ITransportRung? GetRung(string id) => _rungs.TryGetValue(id ?? "", out var r) ? r : null;

    /// <summary>BD-SHARED-TRANSPORT F12: the engine's event list
    /// is a bounded ring — a long-running host must not grow it
    /// forever. The session store's own event lists remain the
    /// durable linkage record.</summary>
    public const int MaxEngineEvents = 512;

    private void Record(string kind, string? rung, string detail, string? from = null, string? to = null)
    {
        lock (_events)
        {
            _events.Add(new TransportEvent(kind, rung, detail, from, to));
            if (_events.Count > MaxEngineEvents) _events.RemoveRange(0, _events.Count - MaxEngineEvents);
        }
    }

    /// <summary>Resolve the ordered rung list a start may walk.
    /// Null = device unknown / no effective transports. A manual
    /// pin narrows within the resolved set (order = set order);
    /// a pin naming a rung outside the set refuses the whole
    /// resolution (never a silent widening, D32).</summary>
    public IReadOnlyList<string>? ResolveOrder(string hostDeviceId, IEnumerable<string>? manualPins = null)
    {
        var effective = _roster.EffectiveTransportsForDevice(hostDeviceId);
        if (effective is null || effective.Count == 0) return null;
        if (manualPins is not null)
        {
            var pins = manualPins.Select(p => (p ?? "").Trim().ToLowerInvariant()).Where(p => p.Length > 0).ToList();
            if (pins.Count == 0) return null;
            if (!pins.All(p => effective.Contains(p, StringComparer.OrdinalIgnoreCase))) return null;
            return effective.Where(e => pins.Contains(e, StringComparer.OrdinalIgnoreCase)).ToList();
        }
        return effective;
    }

    /// <summary>Start a session over the transport layer. The
    /// session is created per candidate rung (so its TransportRung
    /// is always the rung that actually carried it); a rung whose
    /// connection or start gate fails is recorded and the walk
    /// continues. Null when every rung in the order fails.</summary>
    public async Task<Session?> StartSessionAsync(string scopeId, string hostDeviceId, string initiatorUserId,
        string kind, IReadOnlyDictionary<string, TransportTarget> targets, string recording = "none",
        IEnumerable<string>? manualPins = null, CancellationToken ct = default)
    {
        var order = ResolveOrder(hostDeviceId, manualPins);
        if (order is null)
        { Record("start_refused", null, "No effective transports (or a manual pin outside the group's set)."); return null; }
        foreach (var rungId in order)
        {
            if (!_rungs.TryGetValue(rungId, out var rung))
            { Record("rung_unavailable", rungId, "Rung is in the group's set but no implementation is registered in this build."); continue; }
            var target = targets.TryGetValue(rungId, out var t) ? t : new TransportTarget(hostDeviceId);
            TransportConnectResult result;
            if (rung is IAuthenticatedRung authed && _identity is not null)
                result = await authed.ConnectSessionAsync(target, _identity, ct);
            else
                result = await rung.ConnectAsync(target, ct);
            if (!result.Ok)
            { Record("attempt_failed", rungId, result.Detail); result.Stream?.Dispose(); continue; }
            var session = _sessions.CreateSession(scopeId, hostDeviceId, initiatorUserId, kind, rungId, recording);
            if (session is null || !_sessions.StartSession(session.Id, initiatorUserId))
            {
                Record("start_gate_refused", rungId, "Slice 3 start gates refused this rung's session (consent/grant/offboarding).");
                result.Stream?.Dispose();
                if (session is not null) _sessions.EndSession(session.Id, initiatorUserId);
                continue;
            }
            _live[session.Id] = new LiveLink(rungId, target, scopeId, hostDeviceId, initiatorUserId, kind, recording, result.Stream, order);
            Record("session_started", rungId, $"Session started over {rungId}.", null, session.Id);
            return _sessions.GetSession(session.Id);
        }
        Record("start_failed", null, "Every rung in the resolved order failed.");
        return null;
    }

    /// <summary>Re-establish a live session whose rung died, on
    /// the NEXT rung after the dead one in its resolved order.
    /// The old session ends with reason transport_failover; the
    /// new session's replay and the engine log link both ids.
    /// Null when there is no next rung (the floor holds: failover
    /// never leaves the session's resolved set) or the session is
    /// not live.</summary>
    public async Task<Session?> ReestablishAsync(string sessionId, IReadOnlyDictionary<string, TransportTarget> targets, CancellationToken ct = default)
    {
        if (!_live.TryGetValue(sessionId ?? "", out var link)) return null;
        var current = _sessions.GetSession(sessionId);
        if (current is null || current.State is "ended") { _live.Remove(sessionId ?? ""); return null; }
        var idx = link.OrderedRungs.ToList().FindIndex(r => string.Equals(r, link.Rung, StringComparison.OrdinalIgnoreCase));
        var remaining = link.OrderedRungs.Skip(idx + 1).ToList();
        if (remaining.Count == 0)
        { Record("failover_exhausted", link.Rung, "No next rung in the resolved set — the session ends rather than leaving its set.", sessionId, null); return null; }
        // End the old session FIRST: the linkage is end + new-start.
        link.Stream?.Dispose();
        _live.Remove(sessionId ?? "");
        if (!_sessions.EndSessionForFailover(sessionId, link.InitiatorUserId))
        { Record("failover_refused", link.Rung, "The old session could not be ended for failover.", sessionId, null); return null; }
        var next = await StartSessionAsync(link.ScopeId, link.HostDeviceId, link.InitiatorUserId, link.Kind,
            targets, link.Recording, manualPins: remaining, ct: ct);
        // StartSessionAsync resolves manualPins against the CURRENT
        // effective set; `remaining` is a subset of the original
        // order, and ResolveOrder preserves set order — but the new
        // session must start on a REMAINING rung, which the pin
        // guarantees (pins = remaining only).
        if (next is null)
        { Record("failover_failed", link.Rung, "Re-establishment failed on every remaining rung.", sessionId, null); return null; }
        Record("session_reestablished", next.TransportRung,
            $"Reconnected on {next.TransportRung} after {link.Rung} died. This is a reconnect: session {sessionId} ended (transport_failover); session {next.Id} started.",
            sessionId, next.Id);
        _sessions.AppendEvent(next.Id, "transport_failover", link.InitiatorUserId, sessionId,
            $"Re-established after rung '{link.Rung}' died; previous session {sessionId} ended (transport_failover). A reconnect, not a seamless continuation.");
        return next;
    }

    /// <summary>BD-SHARED-TRANSPORT F8: link liveness maintenance.
    /// Previously ReestablishAsync was public but nothing watched
    /// a live link, so a dead rung was only noticed by an outside
    /// caller. MaintainLinkAsync probes the live channel
    /// (PING → PONG under a deadline, over the AEAD channel); a
    /// failed probe triggers ReestablishAsync and returns the new
    /// session. Returns the current session when the link is
    /// healthy, null when the link is unknown or re-establishment
    /// failed. The host runs this on its lane timer; it is also
    /// directly callable (and testable) per link.</summary>
    public async Task<Session?> MaintainLinkAsync(string sessionId,
        IReadOnlyDictionary<string, TransportTarget> targets, CancellationToken ct = default)
    {
        if (!_live.TryGetValue(sessionId ?? "", out var link)) return null;
        var current = _sessions.GetSession(sessionId);
        if (current is null || current.State is "ended") { _live.Remove(sessionId ?? ""); return null; }
        if (link.Stream is null) return current; // stub/dormant links carry no probeable channel
        var alive = false;
        try
        {
            using var probe = CancellationTokenSource.CreateLinkedTokenSource(ct);
            probe.CancelAfter(TimeSpan.FromSeconds(5));
            await LanProtocol.WriteLineAsync(link.Stream, "PING", probe.Token);
            alive = await LanProtocol.ReadLineAsync(link.Stream, probe.Token) == "PONG";
        }
        catch { alive = false; }
        if (alive) return current;
        Record("link_dead", link.Rung, "Live-link probe failed (no PONG under deadline) — re-establishing.", sessionId, null);
        return await ReestablishAsync(sessionId, targets, ct);
    }

    /// <summary>Drop a live link without touching the session model
    /// (the session layer's own end/STOP paths stay authoritative).</summary>
    public void ForgetLink(string sessionId)
    {
        if (_live.TryGetValue(sessionId ?? "", out var link)) { link.Stream?.Dispose(); _live.Remove(sessionId); }
    }
}
