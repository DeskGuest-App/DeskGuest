using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

/// <summary>
/// The LAN lane's host certificate (DESIGN §6.1; closes inspector H1's
/// cleartext-LAN remainder). A self-signed certificate is generated on
/// first Core start and persisted in the data dir (lan-tls/), which
/// the installer ACLs to SYSTEM + Administrators + owner. Its SHA-256
/// fingerprint is the pin: disclosed only inside a successful pairing
/// exchange (which happens on the encrypted tailnet lane), and clients
/// reject the LAN lane unless the presented certificate matches it.
///
/// The PFX password is generated with the certificate.
/// BD-WIN-CORE-3/F11: when an ISecretProtector is wired (CoreRuntime
/// passes the runtime protector — DPAPI on Windows), the password
/// is stored SEALED, never plaintext; the legacy plaintext shape is
/// still readable (and upgraded on next generation) so existing
/// installs do not lose their pin. Files are written
/// temp-file-and-rename (password sealed first, then PFX, then pin)
/// so a crash cannot leave a mismatched pair, and a regeneration
/// after a corrupt store is reported through the audit callback —
/// the pin change is never silent. Without a protector the data-dir
/// ACL remains the boundary, as before. Rotating = delete the
/// lan-tls directory and restart; the pin changes and every client
/// must re-pair (fail-closed by design).
/// </summary>
public sealed class LanCertificateStore
{
    private readonly string _dir;
    private readonly ISecretProtector? _protector;
    private readonly Action<string>? _audit;
    private X509Certificate2? _certificate;

    public LanCertificateStore(string dataDir, ISecretProtector? protector = null,
        Action<string>? audit = null)
    {
        _dir = Path.Combine(dataDir, "lan-tls");
        _protector = protector;
        _audit = audit;
    }

    private static void WriteAtomic(string path, byte[] bytes)
    {
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }

    private static void WriteAtomicText(string path, string text) =>
        WriteAtomic(path, System.Text.Encoding.UTF8.GetBytes(text));

    private string ReadPassword()
    {
        var raw = File.ReadAllText(PasswordPath).Trim();
        if (_protector is not null && raw.StartsWith("sealed:", StringComparison.Ordinal))
            return _protector.Unprotect(raw["sealed:".Length..]);
        return raw; // legacy plaintext shape (pre-F11 stores)
    }

    private string SealPassword(string password) =>
        _protector is null ? password : "sealed:" + _protector.Protect(password);

    private string PfxPath => Path.Combine(_dir, "lan-host.pfx");
    private string PasswordPath => Path.Combine(_dir, "lan-host.password");
    private string PinPath => Path.Combine(_dir, "lan-host.pin");

    /// <summary>Load the persisted certificate, generating and
    /// persisting one on first use. Idempotent: later calls (and later
    /// Core runs) return the SAME certificate, so the pin is stable
    /// across restarts.</summary>
    public X509Certificate2 EnsureCertificate()
    {
        if (_certificate is not null) return _certificate;
        Directory.CreateDirectory(_dir);
        var hadStore = File.Exists(PfxPath) && File.Exists(PasswordPath);
        if (hadStore)
        {
            try
            {
                var password = ReadPassword();
                _certificate = X509CertificateLoader.LoadPkcs12FromFile(PfxPath, password);
                return _certificate;
            }
            catch
            {
                // BD-WIN-CORE-3/F11: regeneration after a corrupt
                // store changes the pin — that is AUDITED, never
                // silent (clients re-pair, fail-closed).
                _audit?.Invoke("lan_tls_store_corrupt_regenerating: the persisted LAN certificate store did not load; a new certificate (and pin) was generated — clients must re-pair");
            }
        }

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN=DeskGuest-Windows LAN host ({Environment.MachineName})",
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") /* serverAuth */ }, critical: false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(Environment.MachineName);
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());

        using var generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        var newPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var pfx = generated.Export(X509ContentType.Pfx, newPassword);
        // BD-WIN-CORE-3/F11: temp-file-and-rename for every file,
        // password (sealed when a protector is wired) first.
        WriteAtomicText(PasswordPath, SealPassword(newPassword));
        WriteAtomic(PfxPath, pfx);
        _certificate = X509CertificateLoader.LoadPkcs12(pfx, newPassword);
        WriteAtomicText(PinPath, Fingerprint);
        if (hadStore)
            _audit?.Invoke($"lan_tls_certificate_regenerated: new LAN certificate pin {Fingerprint}");
        return _certificate;
    }

    /// <summary>The pin clients must demand from the LAN lane.</summary>
    public string Fingerprint => CertificatePinning.Fingerprint(EnsureCertificate());
}
