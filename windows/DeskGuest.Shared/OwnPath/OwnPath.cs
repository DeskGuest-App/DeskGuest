using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.OwnPath;

// =====================================================================
// Own-path rung support (T5 audit, ADOPT WITH NAMED MITIGATIONS —
// conditions implemented here, Block F). BINDING conditions:
//  * Config generation is a SECURITY BOUNDARY (OP-01..OP-04): every
//    WireGuard / OpenSSH config DeskGuest emits is produced by a serializer
//    with field validators — never string interpolation of raw user
//    or device-controlled strings. Hostile names (newlines, section
//    headers, quotes, comment markers) are REFUSED, not sanitized
//    into place.
//  * WireGuard: keys generated ON-DEVICE (WG-02); generated configs
//    carry NO wg-quick hooks (WG-01 — PostUp/PreDown/Table execute
//    as root/SYSTEM) and NO SaveConfig (WG-03); per-peer /32 (v4) or
//    /128 (v6) AllowedIPs (WG-04); no DNS = side effects (WG-04).
//  * OpenSSH: generated config asserts the full deny-list and keys
//    are restrict-class (OP-03/OP-07/OP-08 shape, model layer).
// The fuzz battery over hostile names is a permanent regression
// suite (BlockFTests.OwnPathFuzz_*).
// =====================================================================

public static class OwnPathValidation
{
    /// <summary>A device/peer name that may appear in a generated
    /// config comment. Deliberately narrow: letters, digits, space,
    /// dot, underscore, hyphen; 1..48 chars; no leading/trailing
    /// space. Anything else refuses — a name is a label, never a
    /// config directive.</summary>
    public static bool IsSafeName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 48) return false;
        if (name != name.Trim()) return false;
        if (name.All(c => c == '.')) return false; // "." / ".." are path shapes, never names
        foreach (var c in name)
            if (!(char.IsLetterOrDigit(c) || c is ' ' or '.' or '_' or '-')) return false;
        return true;
    }

    /// <summary>A WireGuard key: exactly 32 bytes, base64, canonical
    /// 44-char form with a single '=' pad.</summary>
    public static bool IsWireGuardKey(string? key)
    {
        if (key is null || key.Length != 44 || !key.EndsWith('=')) return false;
        try { return Convert.FromBase64String(key).Length == 32; }
        catch { return false; }
    }

    /// <summary>An endpoint host:port whose host is a literal IP or a
    /// conservative DNS name (no whitespace, no brackets-in-name, no
    /// config metacharacters).</summary>
    public static bool TryParseEndpoint(string? endpoint, out string host, out int port)
    {
        host = ""; port = 0;
        if (string.IsNullOrWhiteSpace(endpoint)) return false;
        var e = endpoint.Trim();
        if (e.Any(c => char.IsWhiteSpace(c) || c is '#' or ';' or '"' or '\'')) return false;
        string h; string p;
        if (e.StartsWith('[')) // [v6]:port
        {
            var close = e.IndexOf(']');
            if (close < 2 || close + 1 >= e.Length || e[close + 1] != ':') return false;
            h = e[1..close]; p = e[(close + 2)..];
            if (!IPAddress.TryParse(h, out var ip6) || ip6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return false;
        }
        else
        {
            var idx = e.LastIndexOf(':');
            if (idx <= 0) return false;
            h = e[..idx]; p = e[(idx + 1)..];
            if (!IPAddress.TryParse(h, out _))
            {
                // Conservative DNS name: labels of letters/digits/hyphen.
                if (h.Length > 253) return false;
                foreach (var label in h.Split('.'))
                {
                    if (label.Length is 0 or > 63) return false;
                    if (!label.All(c => char.IsLetterOrDigit(c) || c == '-')) return false;
                    if (label.StartsWith('-') || label.EndsWith('-')) return false;
                }
            }
        }
        if (!int.TryParse(p, out port) || port is <= 0 or > 65535) return false;
        host = h;
        return true;
    }

    /// <summary>A tunnel address: a literal IP (the address inside
    /// the WireGuard tunnel). CIDR suffixes are refused here — the
    /// generator itself assigns /32 or /128 (WG-04).</summary>
    public static bool IsTunnelAddress(string? address) =>
        address is not null && IPAddress.TryParse(address.Trim(), out _);
}

/// <summary>One own-path peer as DeskGuest knows it: everything the
/// serializer needs, nothing it doesn't.</summary>
public sealed record OwnPathPeer(
    string DeviceId,
    string DisplayName,
    string PublicKey,
    string TunnelAddress,
    string Endpoint,
    string? PresharedKey = null);

/// <summary>Generates a WireGuard peer config for ONE peer by
/// serialization + validation. The private key is NEVER part of a
/// peer config and never accepted by this generator (WG-02: keys
/// are generated on-device and stay there).</summary>
public static class WireGuardConfigGenerator
{
    public static string GeneratePeerConfig(OwnPathPeer peer)
    {
        // BD-SHARED-TRANSPORT F4(1): DeviceId lands in the config
        // text as a comment — a newline in it would inject whole
        // [Interface] lines / AllowedIPs into the generated file.
        // It is validated with the same safe-name discipline as
        // every other interpolated value (OP-01).
        if (!OwnPathValidation.IsSafeName(peer.DeviceId))
            throw new InvalidOperationException($"ownpath: peer device id '{peer.DeviceId}' is not a safe config value — refused (OP-01)");
        if (!OwnPathValidation.IsSafeName(peer.DisplayName))
            throw new InvalidOperationException($"ownpath: peer name '{peer.DisplayName}' is not a safe config name — refused (OP-01)");
        if (!OwnPathValidation.IsWireGuardKey(peer.PublicKey))
            throw new InvalidOperationException("ownpath: peer public key is not a WireGuard key — refused");
        if (peer.PresharedKey is not null && !OwnPathValidation.IsWireGuardKey(peer.PresharedKey))
            throw new InvalidOperationException("ownpath: preshared key is not a WireGuard key — refused");
        if (!OwnPathValidation.IsTunnelAddress(peer.TunnelAddress))
            throw new InvalidOperationException("ownpath: tunnel address is not a literal IP — refused");
        if (!OwnPathValidation.TryParseEndpoint(peer.Endpoint, out var host, out var port))
            throw new InvalidOperationException("ownpath: endpoint is not a valid host:port — refused");
        var ip = IPAddress.Parse(peer.TunnelAddress.Trim());
        var mask = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        var endpointText = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && host.Contains(':')
            ? $"[{host}]:{port}" : $"{host}:{port}";
        var sb = new StringBuilder();
        sb.AppendLine("# DeskGuest own-path peer (generated; do not hand-edit — regenerate)");
        sb.AppendLine($"# Device: {peer.DeviceId}");
        sb.AppendLine($"# Name: {peer.DisplayName}");
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey = {peer.PublicKey}");
        if (peer.PresharedKey is not null) sb.AppendLine($"PresharedKey = {peer.PresharedKey}");
        sb.AppendLine($"AllowedIPs = {peer.TunnelAddress.Trim()}/{mask}");
        sb.AppendLine($"Endpoint = {endpointText}");
        sb.AppendLine("PersistentKeepalive = 25");
        return sb.ToString();
    }

    /// <summary>The standing validator for ANY WireGuard config text
    /// DeskGuest is asked to use (generated or imported): hooks, SaveConfig
    /// and DNS side effects are refused outright (WG-01/WG-03/WG-04).</summary>
    public static (bool Ok, string Reason) ValidateConfigText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (false, "empty config");
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var eq = line.IndexOf('=');
            var key = (eq >= 0 ? line[..eq] : line).Trim();
            // BD-SHARED-TRANSPORT F4(2): wg-quick lowercases keys,
            // so the comparison is case-insensitive — 'postup = …'
            // previously sailed past the ordinal match.
            var lowered = key.ToLowerInvariant();
            if (lowered is "postup" or "predown" or "postdown" or "preup" or "table" or "saveconfig" or "dns")
                return (false, $"config carries forbidden directive '{key}' (WG-01/WG-03/WG-04) — refused");
            // BD-SHARED-TRANSPORT F4(2): AllowedIPs is checked —
            // a peer config may carry ONLY the peer's own /32 (v4)
            // or /128 (v6); 0.0.0.0/0 would route the whole
            // internet through the "peer".
            if (lowered == "allowedips" && eq >= 0)
            {
                foreach (var entry in line[(eq + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!System.Net.IPNetwork.TryParse(entry, out var net) ||
                        !(net.PrefixLength == 32 && net.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                          net.PrefixLength == 128 && net.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6))
                        return (false, $"AllowedIPs entry '{entry}' is not a single-host /32 or /128 (WG-04) — refused");
                }
            }
        }
        return (true, "config accepted");
    }

    /// <summary>BD-SHARED-TRANSPORT F5: the [Interface] half of a
    /// full tunnel config — GeneratePeerConfig alone produced only
    /// a [Peer] stanza, so the rung could never bring a tunnel up
    /// by itself. The private key comes from the caller's vault
    /// (WG-02: generated on-device, protector-wrapped at rest) and
    /// is serialized here, never logged. Combined with
    /// GeneratePeerConfig this is a complete wg-quick config.</summary>
    public static string GenerateInterfaceConfig(string privateKeyBase64, string tunnelAddress, int listenPort)
    {
        if (!OwnPathValidation.IsWireGuardKey(privateKeyBase64))
            throw new InvalidOperationException("ownpath: interface private key is not a WireGuard key — refused");
        if (!OwnPathValidation.IsTunnelAddress(tunnelAddress))
            throw new InvalidOperationException("ownpath: interface tunnel address is not a literal IP — refused");
        if (listenPort is <= 0 or > 65535)
            throw new InvalidOperationException("ownpath: listen port out of range — refused");
        var ip = IPAddress.Parse(tunnelAddress.Trim());
        var mask = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        var sb = new StringBuilder();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {privateKeyBase64}");
        sb.AppendLine($"Address = {tunnelAddress.Trim()}/{mask}");
        sb.AppendLine($"ListenPort = {listenPort}");
        return sb.ToString();
    }

    /// <summary>A complete tunnel config: [Interface] + [Peer].</summary>
    public static string GenerateTunnelConfig(string privateKeyBase64, string ownTunnelAddress, int listenPort, OwnPathPeer peer) =>
        GenerateInterfaceConfig(privateKeyBase64, ownTunnelAddress, listenPort) + GeneratePeerConfig(peer);

    /// <summary>Generate a fresh WireGuard keypair ON THIS DEVICE
    /// (WG-02). X25519 (RFC 7748) computed in-process over the
    /// clamped random scalar; the private key is returned to the
    /// caller for protector-wrapped storage only — it is never
    /// logged or serialized by this class. The ladder is validated
    /// against the RFC 7748 §5.2 test vector in the test suite.</summary>
    public static (string PrivateKeyBase64, string PublicKeyBase64) GenerateKeyPair()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        var pub = X25519(priv, BasePoint);
        return (Convert.ToBase64String(priv), Convert.ToBase64String(pub));
    }

    private static readonly byte[] BasePoint = new byte[32] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    /// <summary>RFC 7748 X25519: Montgomery ladder over
    /// p = 2^255 − 19 with a24 = 121665. Scalar clamping applied
    /// internally, per the RFC.</summary>
    public static byte[] X25519(byte[] scalar32, byte[] u32)
    {
        var k = (byte[])scalar32.Clone();
        k[0] &= 248; k[31] &= 127; k[31] |= 64;
        var p = (System.Numerics.BigInteger.One << 255) - 19;
        System.Numerics.BigInteger Mod(System.Numerics.BigInteger x) { var r = x % p; return r.Sign < 0 ? r + p : r; }
        System.Numerics.BigInteger Inv(System.Numerics.BigInteger x) =>
            System.Numerics.BigInteger.ModPow(Mod(x), p - 2, p);
        var x1 = LeToBig(u32);
        var x2 = System.Numerics.BigInteger.One; var z2 = System.Numerics.BigInteger.Zero;
        var x3 = x1; var z3 = System.Numerics.BigInteger.One;
        var swap = 0;
        const int a24 = 121665;
        for (var t = 254; t >= 0; t--)
        {
            var kt = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= kt;
            if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
            swap = kt;
            var a = Mod(x2 + z2); var aa = Mod(a * a);
            var b = Mod(x2 - z2); var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3); var d = Mod(x3 - z3);
            var da = Mod(d * a); var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + a24 * e));
        }
        if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
        var result = Mod(x2 * Inv(z2));
        return BigToLe(result);
    }

    private static System.Numerics.BigInteger LeToBig(byte[] le)
    {
        // BigInteger's byte[] constructor IS little-endian two's
        // complement; append a zero byte so the value stays positive.
        var arr = new byte[le.Length + 1];
        Array.Copy(le, arr, le.Length);
        return new System.Numerics.BigInteger(arr);
    }

    private static byte[] BigToLe(System.Numerics.BigInteger v)
    {
        var be = v.ToByteArray(); // little-endian, two's complement
        var outp = new byte[32];
        Array.Copy(be, 0, outp, 0, Math.Min(32, be.Length));
        return outp;
    }
}

/// <summary>The alternate own-path (T5): an OpenSSH client config
/// stanza as configured by DeskGuest. Serializer + validators only; the
/// deny-list is asserted in every generated stanza (OP-03 shape).</summary>
public static class SshChannelConfigGenerator
{
    public static string GenerateHostStanza(string alias, OwnPathPeer peer, string user, string identityFileName)
    {
        if (!OwnPathValidation.IsSafeName(alias))
            throw new InvalidOperationException("ownpath/ssh: alias is not a safe config name — refused (OP-01)");
        if (!OwnPathValidation.TryParseEndpoint(peer.Endpoint, out var host, out var port))
            throw new InvalidOperationException("ownpath/ssh: endpoint is not a valid host:port — refused");
        if (!OwnPathValidation.IsSafeName(user) || user.Contains(' '))
            throw new InvalidOperationException("ownpath/ssh: user is not a safe config value — refused");
        if (identityFileName.Any(c => char.IsWhiteSpace(c) || c is '"' or '\''))
            throw new InvalidOperationException("ownpath/ssh: identity file name is not safe — refused");
        var sb = new StringBuilder();
        sb.AppendLine($"# DeskGuest own-path SSH channel (generated)");
        sb.AppendLine($"Host {alias}");
        sb.AppendLine($"  HostName {host}");
        sb.AppendLine($"  Port {port}");
        sb.AppendLine($"  User {user}");
        sb.AppendLine($"  IdentityFile {identityFileName}");
        sb.AppendLine("  PasswordAuthentication no");
        sb.AppendLine("  KbdInteractiveAuthentication no");
        sb.AppendLine("  ChallengeResponseAuthentication no");
        sb.AppendLine("  PubkeyAuthentication yes");
        sb.AppendLine("  IdentitiesOnly yes");
        sb.AppendLine("  StrictHostKeyChecking yes");
        sb.AppendLine("  ForwardAgent no");
        sb.AppendLine("  ClearAllForwardings yes");
        sb.AppendLine("  MaxAuthTries 3");
        return sb.ToString();
    }

    /// <summary>An authorized_keys line for an DeskGuest channel key:
    /// restrict-class (which itself disables forwarding, pty,
    /// agent/X11 and user-rc), no forwarding re-enabled
    /// (OP-07 shape).</summary>
    public static string GenerateAuthorizedKeyLine(string publicKeyLine, string commentName)
    {
        if (!OwnPathValidation.IsSafeName(commentName))
            throw new InvalidOperationException("ownpath/ssh: key comment is not a safe name — refused");
        var parts = (publicKeyLine ?? "").Trim().Split(' ');
        if (parts.Length < 2 || parts[0] is not ("ssh-ed25519" or "sk-ssh-ed25519@openssh.com"))
            throw new InvalidOperationException("ownpath/ssh: only Ed25519 public keys are accepted — refused");
        if (!parts[1].All(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '='))
            throw new InvalidOperationException("ownpath/ssh: key body is not base64 — refused");
        // BD-SHARED-TRANSPORT F4(3): plain 'restrict' — OpenSSH's
        // restrict already disables port forwarding; the former
        // 'restrict,port-forwarding' form explicitly RE-ENABLED
        // it, contradicting this line's own contract.
        return $"restrict {parts[0]} {parts[1]} deskguest-{commentName.Replace(' ', '-')}";
    }
}

/// <summary>FNV-style stable fingerprint of a generated config, for
/// drift comparison (the config itself may carry key material and
/// is never logged; its hash is safe to record).</summary>
public static class OwnPathFingerprint
{
    public static string Of(string configText) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(configText))).ToLowerInvariant();
}

/// <summary>BD-SHARED-TRANSPORT F5: the tunnel lifecycle the
/// own-path rung's data plane needs, as DeskGuest-owned command shapes
/// (the Windows host service executes them through its service
/// control path; this layer owns the shapes and the up-check so
/// the lifecycle is testable and auditable, not hand-built at the
/// call site). Install uses wireguard.exe's own service
/// installer; the up-check is "the tunnel interface answers at
/// the peer's tunnel address" — the rung's connect is the proof,
/// and a tunnel that is not up fails the connect honestly.</summary>
public static class WireGuardTunnelLifecycle
{
    public static string[] InstallTunnelServiceArgs(string configPath) =>
        new[] { "/installtunnelservice", configPath };
    public static string[] UninstallTunnelServiceArgs(string tunnelName) =>
        new[] { "/uninstalltunnelservice", tunnelName };
    /// <summary>The service name wireguard.exe registers for a
    /// config file (its documented naming: WireGuardTunnel$&lt;name&gt;).</summary>
    public static string ServiceNameFor(string configFileName) =>
        "WireGuardTunnel$" + System.IO.Path.GetFileNameWithoutExtension(configFileName);
}
