using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Services;

/// <summary>
/// C20 WIRING — owner-local recovery-blob acts (export / inspect /
/// restore) over the C20 <see cref="RecoveryBlobService"/>.
///
/// OWNER-LOCAL ONLY, the owner_takeover discipline (BD-WIN-CORE-2):
/// export and restore are acts of the owner at the machine, reached
/// ONLY from CoreRuntime's authenticated companion-window IPC channel
/// (IpcKinds.RecoveryAction). There is deliberately NO MCP tool that
/// performs them — the <see cref="RecoveryBlobModule"/> below exists
/// so an agent pairing that asks is refused in-band, Admin scope
/// included. An agent pairing can neither export this device's
/// identity nor trigger a restore remotely.
///
/// Key-sheet hygiene (destruction-pass rule): the key sheet is
/// returned to the caller ONCE (CoreRuntime forwards it to the
/// companion window over the owner channel and nowhere else). It is
/// NEVER written to the audit log, NEVER placed in an action-result
/// detail, and NEVER persisted. Audit outcomes for this service are
/// FIXED strings plus counts/device ids only — a refusal's exception
/// message can quote a mistyped key-sheet word, so messages are
/// returned to the owner window (the owner typed them) but are never
/// copied into the log.
///
/// Audit kinds (all Kind="system", Tool="recovery_blob"):
///   recovery_exported:&lt;deviceId&gt;:contacts=&lt;n&gt;
///   recovery_export_refused
///   recovery_restored:&lt;deviceId&gt;:pairings=&lt;n&gt;:roster=&lt;n&gt;
///   recovery_restore_refused
/// A successful restore also fires the presence note delegate
/// (narration + agent-event + host-state push in CoreRuntime), so a
/// restore is visible on the endpoint, not silent.
/// </summary>
public sealed class OwnerRecoveryService
{
    private readonly Func<DeviceIdentity> _identity;
    private readonly ISecretProtector _protector;
    private readonly PairingService _pairings;
    private readonly RosterService _roster;
    private readonly IAuditLog _audit;
    private readonly Func<bool> _liveIdentityExists;
    private readonly Action<DeviceIdentity> _applyIdentity;
    private readonly Action<string> _presenceNote;

    public DateTimeOffset? LastExportUtc { get; private set; }
    public DateTimeOffset? LastRestoreUtc { get; private set; }
    public string? LastRestoredDeviceId { get; private set; }
    public int LastRestorePairings { get; private set; }
    public int LastRestoreRosterEntries { get; private set; }

    public OwnerRecoveryService(
        Func<DeviceIdentity> identity,
        ISecretProtector protector,
        PairingService pairings,
        RosterService roster,
        IAuditLog audit,
        Func<bool> liveIdentityExists,
        Action<DeviceIdentity> applyIdentity,
        Action<string> presenceNote)
    {
        _identity = identity;
        _protector = protector;
        _pairings = pairings;
        _roster = roster;
        _audit = audit;
        _liveIdentityExists = liveIdentityExists;
        _applyIdentity = applyIdentity;
        _presenceNote = presenceNote;
    }

    private void Audit(string operation, string outcome) =>
        _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null,
            "recovery_blob", operation, null, outcome, "Owner", null));

    /// <summary>Export the artefact set for the CURRENT identity.
    /// The result carries the key sheet — the caller (CoreRuntime)
    /// forwards it to the owner window once and drops it.</summary>
    public RecoveryExportResult Export(string passphrase, IReadOnlyList<RecoveryContact>? contacts = null)
    {
        try
        {
            var result = RecoveryBlobService.Export(
                _identity(), _protector, _pairings, _roster, passphrase, contacts);
            LastExportUtc = DateTimeOffset.UtcNow;
            Audit("export", $"recovery_exported:{result.DeviceId}:contacts={result.ContactBlobs.Count}");
            return result;
        }
        catch (RecoveryBlobException)
        {
            Audit("export", "recovery_export_refused");
            throw;
        }
    }

    /// <summary>Public metadata of a blob the owner picked. No audit:
    /// inspecting a file the owner is holding is not an act on this
    /// device's state.</summary>
    public RecoveryBlobInfo Inspect(byte[] blob) => RecoveryBlobService.Inspect(blob);

    /// <summary>Restore from a PRIMARY blob (passphrase or key
    /// sheet). Verify-before-touch and the empty-store gate are the
    /// C20 service's; the live-identity gate is the host's delegate
    /// (a never-used identity minted at first boot is replaceable —
    /// see CoreRuntime — a loaded, in-use identity is not). On
    /// success the rebuilt identity is handed to the host's apply
    /// delegate (persist + swap) and a presence note fires.</summary>
    public RecoveryRestoreResult RestorePrimary(byte[] blob, string? passphrase, string? keySheet) =>
        Restore(() => RecoveryBlobService.RestorePrimary(
            blob, passphrase, keySheet, _protector, _pairings, _roster, _liveIdentityExists));

    /// <summary>Restore from a SEALED CONTACT copy (contact seed +
    /// key sheet — both, by C20 design).</summary>
    public RecoveryRestoreResult RestoreFromContactCopy(byte[] blob, byte[] contactSeed, string keySheet) =>
        Restore(() => RecoveryBlobService.RestoreFromContactCopy(
            blob, contactSeed, keySheet, _protector, _pairings, _roster, _liveIdentityExists));

    private RecoveryRestoreResult Restore(Func<RecoveryRestoreResult> act)
    {
        RecoveryRestoreResult result;
        try { result = act(); }
        catch (RecoveryBlobException)
        {
            Audit("restore", "recovery_restore_refused");
            throw;
        }
        _applyIdentity(result.Identity);
        LastRestoreUtc = DateTimeOffset.UtcNow;
        LastRestoredDeviceId = result.DeviceId;
        LastRestorePairings = result.PairingsRestored;
        LastRestoreRosterEntries = result.RosterEntriesRestored;
        Audit("restore", $"recovery_restored:{result.DeviceId}:pairings={result.PairingsRestored}:roster={result.RosterEntriesRestored}");
        _presenceNote($"recovery_restored:{result.DeviceId}");
        return result;
    }
}

/// <summary>The agent-facing surface for recovery: a refusal, in the
/// OwnerTakeoverModule idiom. Export/restore are owner-local acts;
/// no pairing — Admin scope included — can invoke them, and the blob
/// itself never transits a tool call.</summary>
public sealed class RecoveryBlobModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "recovery_blob", "Recovery blob status surface. Export and restore are OWNER-LOCAL acts: they happen only from the host window on the machine itself — never through an agent pairing (any scope, Admin included). This tool exists so an agent can be TOLD that, in-band.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["export","restore","inspect"]}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Error("owner_only",
            "recovery_blob is not agent-callable: exporting or restoring a recovery blob is an owner-local act performed from the host window on the machine itself. An agent pairing — Admin scope included — can neither export this device's identity and pairings nor trigger a restore. If recovery is needed, the owner does it at the machine."));
}
