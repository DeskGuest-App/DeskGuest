using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.Security;

/// <summary>
/// Protects pairing-token material at rest. On Windows this is DPAPI
/// (DESIGN §6.2: tokens live in DPAPI-protected storage). The DPAPI
/// implementation compiles anywhere; ProtectedData is Windows-only at
/// runtime and throws elsewhere — callers on non-Windows dev hosts use
/// <see cref="DevOnlyPassThroughProtector"/> and the self-check reports
/// the token store AMBER there, never silently "protected".
/// </summary>
public interface ISecretProtector
{
    string Name { get; }
    bool IsRealProtection { get; }
    string Protect(string plaintext);
    string Unprotect(string protectedText);
}

public sealed class DpapiSecretProtector : ISecretProtector
{
    public string Name => "dpapi";
    public bool IsRealProtection => OperatingSystem.IsWindows();

    public string Protect(string plaintext)
    {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var protectedBytes = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    public string Unprotect(string protectedText)
    {
        var bytes = Convert.FromBase64String(protectedText);
        var plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plain);
    }
}

/// <summary>DEV/TEST ONLY. Stores secrets unprotected (base64). Exists so the
/// pairing/policy suites can run on the Linux build VM. Production Windows
/// installs always use <see cref="DpapiSecretProtector"/>; the self-check
/// reports RED if this protector is in force on a Windows host.</summary>
public sealed class DevOnlyPassThroughProtector : ISecretProtector
{
    public string Name => "dev-passthrough";
    public bool IsRealProtection => false;
    public string Protect(string plaintext) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
    public string Unprotect(string protectedText) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(protectedText));
}
