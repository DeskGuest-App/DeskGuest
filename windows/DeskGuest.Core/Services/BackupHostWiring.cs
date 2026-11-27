using DeskGuest.Shared.Backup;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

/// <summary>
/// W11 / R-15: the production construction site for the backup
/// feature (RMM-06). Before this wiring, CoreRuntime constructed
/// BackupService over an InMemoryBackupStorage + a
/// FakeBackupCaptureSource — an honest-stub comment admitted the
/// runs "exercise the engine shape only", which meant the shipped
/// host's backups contained nothing, persisted nothing, and were
/// encrypted with nothing. This factory is what the header on
/// BackupService always said the host owed:
///
///   * PER-TARGET stores: for every storage target in THIS
///     device's effective backup policy, one BackupSnapshotStore
///     over DirectoryBackupStorage rooted at the target's locator
///     (local absolute paths and NAS/site-server UNC paths are
///     directory shapes; a HUB target's locator is a hub device
///     id, not a path — that leg is hub-side storage and refuses
///     BY NAME in the report below, never silently rerouted).
///   * AT-REST KEY per target: BackupAtRest.LoadOrCreateKeyFile
///     under &lt;DataDir&gt;/backup-keys/&lt;target&gt;.key, wrapped by the
///     host's ISecretProtector (DPAPI in production). The key file
///     NEVER lives at the target: a stolen backup tree yields
///     sealed blobs and no key. A corrupt key file refuses the
///     target by name (LoadOrCreateKeyFile never re-mints over an
///     existing history) — one bad target never blocks the rest.
///   * CATALOGUE persistence: each store's catalogue is reloaded
///     from &lt;DataDir&gt;/backup-catalogues/&lt;target&gt;.json when
///     present (a tampered file imports as TAMPERED inside the
///     store and its restores refuse by name — the store's own
///     discipline), and the service's catalogue-dirty hook writes
///     it back after every mutating act.
///   * CAPTURE: FileBackupCaptureSource — real files, honestly
///     not VSS-consistent; image jobs refuse by name.
///
/// Targets are read from policy AT CONSTRUCTION (this Core is
/// single-device; targets for the local device). A policy change
/// that adds a target takes effect at the next Core start, and a
/// job naming an unwired target refuses by name in BackupService
/// until then — visible, audited, never silently absorbed.
/// </summary>
public static class BackupHostWiring
{
    /// <summary>One line per policy target: wired (with its key
    /// fingerprint) or refused (with the reason). The report is
    /// the wiring's honesty surface — CoreRuntime audits it.</summary>
    public sealed record WiringReport(
        IReadOnlyList<string> Wired,
        IReadOnlyList<string> Refused)
    {
        public string Summary =>
            $"backup host wiring: {Wired.Count} target(s) wired [{string.Join("; ", Wired)}]" +
            (Refused.Count == 0 ? "" : $" | {Refused.Count} refused [{string.Join("; ", Refused)}]");
    }

    public static (BackupService Service, WiringReport Report) Build(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        IDeviceFacts? localFacts,
        string dataDir,
        ISecretProtector protector,
        SignedCommandGate? gate,
        IBackupCaptureSource? capture = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(factsByDevice);
        ArgumentNullException.ThrowIfNull(dataDir);
        ArgumentNullException.ThrowIfNull(protector);

        capture ??= new FileBackupCaptureSource();
        var wired = new List<string>();
        var refused = new List<string>();
        var engines = new Dictionary<string, BackupEngine>(StringComparer.OrdinalIgnoreCase);

        var targets = localFacts is null
            ? Array.Empty<BackupStorageTarget>()
            : BackupPolicyContent.Parse(policy.ComputeEffective(localFacts)).Targets;

        var keysDir = Path.Combine(dataDir, "backup-keys");
        var cataloguesDir = Path.Combine(dataDir, "backup-catalogues");

        foreach (var target in targets)
        {
            if (engines.ContainsKey(target.Id)) continue; // first definition wins; Parse already dedupes by construction in policy order
            if (target.Validate() is { } invalid)
            {
                refused.Add($"target '{target.Id}': {invalid}");
                continue;
            }
            if (target.Kind == BackupTargetKinds.Hub)
            {
                refused.Add($"target '{target.Id}': hub targets name a hub device id ('{target.Locator}'), not a directory this host can root storage at — hub-side backup storage is not wired on an endpoint host");
                continue;
            }
            byte[] key;
            try
            {
                key = BackupAtRest.LoadOrCreateKeyFile(
                    Path.Combine(keysDir, SafeFileName(target.Id) + ".key"), protector);
            }
            catch (Exception ex)
            {
                refused.Add($"target '{target.Id}': at-rest key refused — {ex.Message}");
                continue;
            }
            BackupSnapshotStore store;
            try
            {
                store = new BackupSnapshotStore(target.Id,
                    new DirectoryBackupStorage(target.Locator), timeVerifier: null, atRestKey: key);
            }
            catch (Exception ex)
            {
                refused.Add($"target '{target.Id}': directory storage at '{target.Locator}' refused — {ex.Message}");
                continue;
            }
            var cataloguePath = Path.Combine(cataloguesDir, SafeFileName(target.Id) + ".json");
            var catalogueNote = "fresh catalogue";
            if (File.Exists(cataloguePath))
            {
                var (ok, summary) = store.LoadCatalogueFromFile(cataloguePath);
                catalogueNote = ok ? $"catalogue reloaded ({summary})" : $"catalogue load refused: {summary}";
            }
            engines[target.Id] = new BackupEngine(store, capture, audit);
            wired.Add($"target '{target.Id}' ({target.Kind} at '{target.Locator}', at-rest key {BackupAtRest.KeyId(key)}, {catalogueNote})");
        }

        var service = new BackupService(audit, policy, factsByDevice, engines, gate,
            catalogueDirty: targetId =>
            {
                if (engines.TryGetValue(targetId, out var engine))
                {
                    Directory.CreateDirectory(cataloguesDir);
                    engine.Store.SaveCatalogueToFile(
                        Path.Combine(cataloguesDir, SafeFileName(targetId) + ".json"));
                }
            });
        return (service, new WiringReport(wired, refused));
    }

    /// <summary>Target ids are policy content — keep them out of
    /// path construction verbatim. Anything outside [A-Za-z0-9._-]
    /// becomes '_'; a leading dot is stripped so no hidden-file or
    /// traversal shape survives.</summary>
    internal static string SafeFileName(string targetId)
    {
        var chars = (targetId ?? "").Select(c =>
            char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_').ToArray();
        var name = new string(chars).TrimStart('.');
        return name.Length == 0 ? "target" : name;
    }
}
