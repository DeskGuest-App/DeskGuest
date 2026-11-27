using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DeskGuest.Shared.Security;

/// <summary>
/// Certificate pinning for the LAN lane (DESIGN §6.1, inspector H1
/// remainder): the Core serves the LAN lane over TLS with a self-signed
/// host certificate generated at install; at pairing time the client
/// receives the certificate's SHA-256 fingerprint (the "pin") over the
/// already-encrypted tailnet lane, and from then on accepts the LAN
/// lane ONLY if the presented certificate hashes to that pin. A pin
/// mismatch is a hard rejection — there is no "proceed anyway" path.
/// </summary>
public static class CertificatePinning
{
    /// <summary>SHA-256 fingerprint of a certificate, uppercase hex —
    /// the canonical pin form used on the wire and on disk.</summary>
    public static string Fingerprint(X509Certificate2 certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256);

    /// <summary>Constant-time pin check. Null/empty pins and missing
    /// certificates never validate: pinning fails closed.</summary>
    public static bool MatchesPin(X509Certificate2? presented, string? expectedPin)
    {
        if (presented is null || string.IsNullOrWhiteSpace(expectedPin)) return false;
        var actual = Fingerprint(presented);
        var expected = expectedPin.Trim().ToUpperInvariant();
        if (actual.Length != expected.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(actual),
            System.Text.Encoding.ASCII.GetBytes(expected));
    }
}
