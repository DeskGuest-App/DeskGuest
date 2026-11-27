using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Hub;

// =====================================================================
// Lane A (Completion Programme) — hub store persistence envelope.
//
// RMM-04's InventoryStore proved the shape (ExportJson/ImportJson +
// CoreRuntime write-through on Changed). This helper gives the
// RMM-05/09/12/16 hub stores the same pattern with STRONGER
// corruption behaviour than the template:
//   * INTEGRITY: the payload is wrapped in an envelope carrying a
//     SHA-256 of the payload. A bit-flip, truncation or hand-edit
//     is DETECTED on load (ImportEnvelope returns null) instead of
//     silently importing partial state.
//   * RECOVERY: CoreRuntime's loader preserves a corrupt file
//     byte-for-byte under a .corrupt-<timestamp> name before the
//     store starts empty (the device-identity discipline), so a
//     damaged store is evidence, never silently overwritten.
//   * Import is always into validated store paths: each store's
//     ImportJson re-runs its own admission/validation rules, so a
//     tampered-but-hash-valid file still cannot plant state the
//     store would have refused live.
// =====================================================================

public static class HubPersistence
{
    private sealed record Envelope(string Kind, string Sha256, string Payload);

    public static string Wrap(string kind, string payloadJson)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payloadJson))).ToLowerInvariant();
        return JsonSerializer.Serialize(new Envelope(kind, hash, payloadJson));
    }

    /// <summary>Unwrap an envelope. Returns null on ANY problem:
    /// unparseable JSON, wrong kind, or a payload whose hash does
    /// not recompute (tamper/corruption). Never throws.</summary>
    public static string? Unwrap(string? envelopeJson, string expectedKind)
    {
        if (string.IsNullOrWhiteSpace(envelopeJson)) return null;
        Envelope? env;
        try { env = JsonSerializer.Deserialize<Envelope>(envelopeJson); }
        catch { return null; }
        if (env is null || env.Payload is null) return null;
        if (!string.Equals(env.Kind, expectedKind, StringComparison.Ordinal)) return null;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(env.Payload))).ToLowerInvariant();
        return string.Equals(hash, env.Sha256, StringComparison.Ordinal) ? env.Payload : null;
    }
}
