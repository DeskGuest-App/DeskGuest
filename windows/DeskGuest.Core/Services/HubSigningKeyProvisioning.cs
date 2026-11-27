using System.Security.Cryptography;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// Lane A (item 3) — hub signing-key provisioning for FL-28a.
//
// FL-28a's mechanism (keyed HMAC snapshot signatures in
// HealthScoreStore) existed with NO key source: hosts provisioned
// nothing, so every store ran unkeyed and imports stayed
// hash+integrity only. This service is the key source:
//
//   * GENERATE-OR-IMPORT at hub setup: ProvisionOrLoad generates a
//     fresh 32-byte key on first run, or loads the sealed key file
//     on later runs. ImportKey accepts a customer-supplied key
//     (base64, exactly 32 bytes) — the key is CUSTOMER-HELD: DeskGuest
//     generates it on the customer's hub, seals it with the hub's
//     ISecretProtector (DPAPI on Windows), and never transmits it.
//   * SEALED STORAGE: the key file holds ONLY protector-sealed
//     base64 (hub-signing-key.txt in the data dir). A plaintext key
//     never touches disk; a file that does not unseal is PRESERVED
//     as corrupt evidence and a fresh key is then generated —
//     loudly, as a chained audit event, never silently and never
//     reusing the tampered material (BD-WIN-CORE-3/F9: this header
//     previously claimed provisioning stayed UNPROVISIONED in that
//     case; the code — and its destruction tests — do the
//     preserve-and-regenerate act described here).
//   * ROTATION (consistent with RMM-03's ring story): Rotate()
//     retires the current key to hub-signing-key.prev.txt with a
//     retired-until timestamp (+30 days); the store verifies
//     snapshots under current-or-retired keys during the window
//     and signs only under the current key — the same
//     sign-current / verify-retired shape as CustomerCommandKeyRing.
//   * Every act (provision, import, rotate, corrupt-preserve) is a
//     chained audit event. Until provisioned, CurrentKey is null
//     and FL-28a imports stay hash+integrity only, exactly as
//     before — named in the state report, never silent.
// =====================================================================

public sealed class HubSigningKeyProvisioning
{
    public const string CurrentFileName = "hub-signing-key.txt";
    public const string PreviousFileName = "hub-signing-key.prev.txt";
    public static readonly TimeSpan RetiredVerifyWindow = TimeSpan.FromDays(30);

    private readonly string _dataDir;
    private readonly ISecretProtector _protector;
    private readonly ChainedAuditLog _audit;
    private readonly Func<DateTimeOffset> _now;

    public byte[]? CurrentKey { get; private set; }
    public byte[]? PreviousKey { get; private set; }
    public DateTimeOffset? PreviousRetiredUntilUtc { get; private set; }
    public bool IsProvisioned => CurrentKey is not null;
    public string State => IsProvisioned
        ? $"provisioned (signing key sealed at rest by '{_protector.Name}'; imports require FL-28a signatures" +
          (PreviousKey is not null ? $"; previous key verifies until {PreviousRetiredUntilUtc:O}" : "") + ")"
        : "unprovisioned — no hub signing key; FL-28a snapshot imports stay hash+integrity only";

    public HubSigningKeyProvisioning(string dataDir, ISecretProtector protector,
        ChainedAuditLog audit, Func<DateTimeOffset>? now = null)
    {
        _dataDir = dataDir ?? throw new ArgumentNullException(nameof(dataDir));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    private string CurrentPath => Path.Combine(_dataDir, CurrentFileName);
    private string PreviousPath => Path.Combine(_dataDir, PreviousFileName);

    private byte[]? TryLoadSealed(string path, string kind)
    {
        if (!File.Exists(path)) return null;
        try
        {
            var text = File.ReadAllText(path).Trim();
            // Previous-key file format: <retiredUntilUtc:O>|<sealed>
            if (kind == "prev")
            {
                var sep = text.IndexOf('|');
                if (sep < 0) return null;
                if (!DateTimeOffset.TryParse(text[..sep], out var until)) return null;
                PreviousRetiredUntilUtc = until;
                text = text[(sep + 1)..];
            }
            var raw = Convert.FromBase64String(_protector.Unprotect(text));
            return raw.Length == 32 ? raw : null;
        }
        catch { return null; }
    }

    private void PreserveCorrupt(string path)
    {
        try
        {
            var corrupt = path + ".corrupt-" + _now().ToString("yyyyMMddHHmmss");
            if (File.Exists(corrupt)) corrupt += "-" + Guid.NewGuid().ToString("N")[..8];
            File.Move(path, corrupt);
        }
        catch { /* best-effort preservation */ }
    }

    private void SealCurrent(byte[] key)
    {
        var sealedText = _protector.Protect(Convert.ToBase64String(key));
        var tmp = CurrentPath + ".tmp";
        File.WriteAllText(tmp, sealedText);
        File.Move(tmp, CurrentPath, overwrite: true);
    }

    /// <summary>Hub-setup provisioning: load the sealed key when one
    /// exists; generate + seal a fresh customer-held key when none
    /// does. A sealed file that no longer unseals is preserved as
    /// corrupt and a NEW key is generated (the rotation is audited —
    /// old snapshots signed under the lost key will fail signature
    /// verification and are refused on import, never silently
    /// accepted).</summary>
    public void ProvisionOrLoad()
    {
        PreviousKey = TryLoadSealed(PreviousPath, "prev");
        if (PreviousKey is not null && PreviousRetiredUntilUtc is { } until && until <= _now())
        {
            // Retired window closed: the old key verifies nothing more.
            // BD-WIN-CORE-3/F9: the deletion is AUDITED — destroying
            // a verify key is a provenance act, not housekeeping.
            PreviousKey = null;
            try { File.Delete(PreviousPath); } catch { }
            _audit.Append("hub_signing_key_previous_expired", "hub-setup",
                $"retired previous signing key deleted: its verify window closed at {until:O}", _now());
        }
        var loaded = TryLoadSealed(CurrentPath, "current");
        if (loaded is not null)
        {
            CurrentKey = loaded;
            _audit.Append("hub_signing_key_loaded", "hub-setup",
                $"signing key loaded from sealed storage (protector={_protector.Name})", _now());
            return;
        }
        if (File.Exists(CurrentPath))
        {
            PreserveCorrupt(CurrentPath);
            _audit.Append("hub_signing_key_corrupt_preserved", "hub-setup",
                "sealed signing-key file did not unseal; preserved as corrupt and a fresh key generated", _now());
        }
        CurrentKey = RandomNumberGenerator.GetBytes(32);
        SealCurrent(CurrentKey);
        _audit.Append("hub_signing_key_provisioned", "hub-setup",
            $"hub signing key generated on this hub and sealed at rest (protector={_protector.Name}); customer-held, never transmitted", _now());
    }

    /// <summary>Import a customer-supplied key (base64, 32 bytes).
    /// Refuses anything else by name; the imported key replaces the
    /// current key WITHOUT a verify window for the replaced one
    /// (an import is an operator's deliberate act — use Rotate for
    /// a windowed transition).</summary>
    public (bool Ok, string Reason) ImportKey(string? base64Key, string actor = "hub-setup")
    {
        // BD-WIN-CORE-3/F9: import/rotate name their ACTOR and the
        // audit carries it — the old shape hard-coded 'hub-setup'
        // for every act, so no record showed WHO replaced the key.
        if (string.IsNullOrWhiteSpace(actor))
            return (false, "key import requires a named actor — refused (anonymous key replacement carries no provenance)");
        byte[] raw;
        try { raw = Convert.FromBase64String((base64Key ?? "").Trim()); }
        catch { return (false, "the presented key is not base64 — import refused"); }
        if (raw.Length != 32)
            return (false, $"the presented key is {raw.Length} bytes — a hub signing key is exactly 32 bytes; import refused");
        CurrentKey = raw;
        SealCurrent(raw);
        _audit.Append("hub_signing_key_imported", actor.Trim(),
            "customer-supplied hub signing key imported and sealed at rest", _now());
        return (true, "hub signing key imported and sealed");
    }

    /// <summary>Rotate: retire the current key to verify-only for
    /// the retired window and generate the new signing key.</summary>
    public (bool Ok, string Reason) Rotate(string actor = "hub-setup")
    {
        if (string.IsNullOrWhiteSpace(actor))
            return (false, "key rotation requires a named actor — refused");
        if (CurrentKey is null)
            return (false, "no signing key is provisioned — rotation refused (provision first)");
        var until = _now() + RetiredVerifyWindow;
        var sealedPrev = _protector.Protect(Convert.ToBase64String(CurrentKey));
        var tmp = PreviousPath + ".tmp";
        File.WriteAllText(tmp, $"{until:O}|{sealedPrev}");
        File.Move(tmp, PreviousPath, overwrite: true);
        PreviousKey = CurrentKey;
        PreviousRetiredUntilUtc = until;
        CurrentKey = RandomNumberGenerator.GetBytes(32);
        SealCurrent(CurrentKey);
        _audit.Append("hub_signing_key_rotated", actor.Trim(),
            $"hub signing key rotated; previous key verifies until {until:O} (RMM-03 retired-key shape)", _now());
        return (true, $"signing key rotated; previous key verifies until {until:O}");
    }
}
