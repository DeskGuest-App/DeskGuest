using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Hub;

/// <summary>DeskGuest-side enforcement Headscale cannot do itself (audit §8.4–§8.6)
/// plus the hub lifecycle. All secrets pass through the existing
/// ISecretProtector; plaintext keys exist only in the caller's hands at
/// mint time and are never persisted, logged, or exported by this code.</summary>

// ------------------------------------------------- HS-02/HS-06 key authority

/// <summary>BD-SHARED-TRANSPORT F2: the ONLY source of real
/// Headscale keys. DeskGuest previously INVENTED the pre-auth key and
/// the "API key" locally as random strings in Headscale's format —
/// a real Headscale rejects both, because it never issued them.
/// Keys now come from Headscale itself, through this seam: the
/// production implementation drives the bundled headscale binary
/// (`preauthkeys create` / `apikeys create`) or its gRPC API and
/// returns what Headscale issued; the vault/join services merely
/// STORE and consume what it returns. No authority wired ⇒ the
/// mint paths refuse (fail closed), they never fabricate.</summary>
public interface IHeadscaleKeyAuthority
{
    /// <summary>Create a single-use pre-auth key on the hub for
    /// the given hub user, expiring after <paramref name="lifetime"/>.
    /// Returns Headscale's key plaintext, or null on failure.</summary>
    string? CreatePreAuthKey(string hubUser, TimeSpan lifetime);
    /// <summary>Create an API key on the hub. Returns Headscale's
    /// key plaintext, or null on failure.</summary>
    string? CreateApiKey(TimeSpan lifetime);
}

/// <summary>Command-line shapes + output parsing for the
/// production authority (the bundled headscale binary). Pure and
/// testable: the process execution itself is the thin shell
/// around these.</summary>
public static class HeadscaleCli
{
    public static string[] PreAuthKeyCreateArgs(string hubUser, TimeSpan lifetime) =>
        new[] { "preauthkeys", "create", "--user", hubUser, "--reusable=false",
                "--expiration", $"{(int)lifetime.TotalMinutes}m", "-o", "json" };
    public static string[] ApiKeyCreateArgs(TimeSpan lifetime) =>
        new[] { "apikeys", "create", "--expiration", $"{(int)lifetime.TotalDays}d", "-o", "json" };
    public static string[] NodesListArgs() => new[] { "nodes", "list", "-o", "json" };

    public static string? ParseCreatedKey(string? cliJson, string property)
    {
        if (string.IsNullOrWhiteSpace(cliJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(cliJson);
            return doc.RootElement.TryGetProperty(property, out var k) ? k.GetString() : null;
        }
        catch { return null; }
    }

    /// <summary>Map DeskGuest device ids to Headscale numeric node ids
    /// from `headscale nodes list -o json` output: nodes carry
    /// "id" (numeric, as string) and "name" — DeskGuest enrolls devices
    /// under their DeviceId as the node name, so the map is
    /// name → id for names that are known DeskGuest device ids.</summary>
    public static IReadOnlyDictionary<string, string> ParseNodeIds(string? cliJson, IReadOnlySet<string> deviceIds)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(cliJson)) return map;
        try
        {
            using var doc = JsonDocument.Parse(cliJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return map;
            foreach (var node in doc.RootElement.EnumerateArray())
            {
                var name = node.TryGetProperty("name", out var n) ? n.GetString() : null;
                var id = node.TryGetProperty("id", out var i) ? i.ToString() : null;
                if (name is not null && id is not null && deviceIds.Contains(name)) map[name] = id;
            }
        }
        catch { /* unparseable hub output maps nothing — Decommission stays refused, by name */ }
        return map;
    }
}

// ---------------------------------------------------------------- HS-02 vault

public sealed record HubApiKeyRecord(
    string Id, string Prefix, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc, bool Revoked);

/// <summary>API keys treated as root credentials (HS-02: every Headscale API
/// key is an unscoped superadmin). Vault-held via ISecretProtector, expiry
/// capped at 90 days and enforced here, rotation = mint-new + revoke-old.
/// The store's export contains ONLY protector-wrapped secrets.</summary>
public sealed class HubApiKeyVault
{
    private sealed class Entry
    {
        public required HubApiKeyRecord Record { get; set; }
        public required string ProtectedSecret { get; set; }
    }

    private readonly ISecretProtector _protector;
    private readonly IHeadscaleKeyAuthority? _authority;
    private readonly Dictionary<string, Entry> _entries = new();
    private readonly object _gate = new();

    /// <param name="authority">BD-SHARED-TRANSPORT F2: the
    /// Headscale key authority. Mint asks IT for a key and vaults
    /// what Headscale issued. Null ⇒ Mint refuses: DeskGuest does not
    /// fabricate hub credentials.</param>
    public HubApiKeyVault(ISecretProtector protector, IHeadscaleKeyAuthority? authority = null)
    { _protector = protector; _authority = authority; }

    public event Action? Changed;

    /// <summary>Mints a key. Returns the record and the one-time plaintext
    /// (shown once, exactly like Headscale — the vault keeps only the
    /// wrapped form). Refuses lifetimes over the 90-day cap.</summary>
    public (HubApiKeyRecord Record, string PlaintextOnce) Mint(TimeSpan lifetime, DateTimeOffset now)
    {
        if (lifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "API key lifetime must be positive");
        if (lifetime > HubPins.MaxApiKeyLifetime)
            throw new InvalidOperationException(
                $"API key lifetime {lifetime.TotalDays:0.#}d exceeds the HS-02 cap of {HubPins.MaxApiKeyLifetime.TotalDays:0}d — refused");
        // BD-SHARED-TRANSPORT F2: the plaintext is Headscale's own
        // issued key, never a locally invented string in its
        // format (a real hub rejects keys it never issued).
        var plaintext = _authority?.CreateApiKey(lifetime)
            ?? throw new InvalidOperationException(
                "no Headscale key authority wired — DeskGuest cannot mint a hub API key locally; keys are issued by Headscale itself (apikeys create) and only vaulted here");
        var prefix = plaintext.Length > 18 ? plaintext[..18] : plaintext;
        var record = new HubApiKeyRecord(
            Id: Guid.NewGuid().ToString("N"),
            Prefix: prefix,
            CreatedUtc: now,
            ExpiresUtc: now + lifetime,
            Revoked: false);
        lock (_gate)
            _entries[record.Id] = new Entry { Record = record, ProtectedSecret = _protector.Protect(plaintext) };
        Changed?.Invoke();
        return (record, plaintext);
    }

    /// <summary>True only for a known, unrevoked, unexpired key id. Expiry is
    /// enforced by DeskGuest because a vault entry that outlives its cap must not
    /// be usable even if the hub-side key was minted carelessly.</summary>
    public bool IsUsable(string keyId, DateTimeOffset now)
    {
        lock (_gate)
            return _entries.TryGetValue(keyId, out var e) && !e.Record.Revoked && now < e.Record.ExpiresUtc;
    }

    /// <summary>The ONLY reveal path: hands the plaintext to the DeskGuest admin
    /// channel for a hub API call. Refuses expired/revoked keys.</summary>
    public string RevealForUse(string keyId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(keyId, out var e))
                throw new InvalidOperationException("unknown API key id");
            if (e.Record.Revoked) throw new InvalidOperationException("API key is revoked");
            if (now >= e.Record.ExpiresUtc) throw new InvalidOperationException("API key is expired — rotate instead of using");
            return _protector.Unprotect(e.ProtectedSecret);
        }
    }

    public void Revoke(string keyId)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(keyId, out var e))
                _entries[keyId] = new Entry { Record = e.Record with { Revoked = true }, ProtectedSecret = e.ProtectedSecret };
        }
        Changed?.Invoke();
    }

    /// <summary>Rotation: mint a fresh key and revoke the old one atomically
    /// from the caller's perspective.</summary>
    public (HubApiKeyRecord Record, string PlaintextOnce) Rotate(string oldKeyId, TimeSpan lifetime, DateTimeOffset now)
    {
        var minted = Mint(lifetime, now);
        Revoke(oldKeyId);
        return minted;
    }

    public IReadOnlyList<HubApiKeyRecord> List()
    {
        lock (_gate) return _entries.Values.Select(e => e.Record).ToList();
    }

    public string ExportJson()
    {
        lock (_gate)
        {
            var dto = _entries.Values.Select(e => new
            {
                e.Record.Id, e.Record.Prefix, e.Record.CreatedUtc, e.Record.ExpiresUtc, e.Record.Revoked,
                secret = e.ProtectedSecret,
                protector = _protector.Name,
            }).ToList();
            return JsonSerializer.Serialize(dto);
        }
    }

    public void ImportJson(string json)
    {
        var doc = JsonDocument.Parse(json);
        lock (_gate)
        {
            _entries.Clear();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                try
                {
                    var record = new HubApiKeyRecord(
                        el.GetProperty("Id").GetString()!,
                        el.GetProperty("Prefix").GetString()!,
                        el.GetProperty("CreatedUtc").GetDateTimeOffset(),
                        el.GetProperty("ExpiresUtc").GetDateTimeOffset(),
                        el.GetProperty("Revoked").GetBoolean());
                    _entries[record.Id] = new Entry
                    {
                        Record = record,
                        ProtectedSecret = el.GetProperty("secret").GetString()!,
                    };
                }
                catch { /* malformed entries skipped, never fatal (PairingService pattern) */ }
            }
        }
    }
}

// ------------------------------------------------------- HS-03 client floor

public sealed record ClientFloorRefusal(string PresentedVersion, DateTimeOffset Utc, string Reason);

/// <summary>Enforces Tailscale ≥ 1.104.4 at DeskGuest's join gate (HS-03 — the
/// server cannot). Fail-closed: unparseable versions are refused, and every
/// refusal is recorded.</summary>
public sealed class ClientVersionGate
{
    public static readonly Version Floor = Version.Parse(HubPins.MinTailscaleClient);
    private readonly List<ClientFloorRefusal> _refusals = new();
    private readonly object _gate = new();

    public IReadOnlyList<ClientFloorRefusal> Refusals
    {
        get { lock (_gate) return _refusals.ToList(); }
    }

    public static bool TryParseClientVersion(string? presented, out Version version)
    {
        version = new Version(0, 0);
        if (string.IsNullOrWhiteSpace(presented)) return false;
        var s = presented.Trim().TrimStart('v', 'V');
        // Tailscale versions arrive as "1.104.4", "1.104.7-t…", "1.104.4-…".
        var cut = s.IndexOfAny(new[] { '-', '+', ' ' });
        if (cut > 0) s = s[..cut];
        return Version.TryParse(s, out version!);
    }

    /// <summary>Returns true when the node may join. On refusal, records it.</summary>
    public bool Admit(string? presentedVersion, DateTimeOffset now)
    {
        if (!TryParseClientVersion(presentedVersion, out var v))
        {
            Record(presentedVersion ?? "", now, "unparseable client version — fail closed (HS-03)");
            return false;
        }
        if (v < Floor)
        {
            Record(presentedVersion!, now, $"client {v} is below the ≥{Floor} floor (HS-03, Tailworm fixes)");
            return false;
        }
        return true;
    }

    /// <summary>BD-SHARED-TRANSPORT F9: the floor question without
    /// the refusal recording — re-verification paths (MeshRung's
    /// per-connect recheck) ask it repeatedly and must not flood
    /// the refusal log for one drift.</summary>
    public bool TryAdmitQuiet(string? presentedVersion) =>
        TryParseClientVersion(presentedVersion, out var v) && v >= Floor;

    /// <summary>BD-SHARED-TRANSPORT F12: refusals are a bounded
    /// ring (512) — the log is evidence, not a growth surface.</summary>
    public const int MaxRefusals = 512;

    private void Record(string presented, DateTimeOffset now, string reason)
    {
        lock (_gate)
        {
            _refusals.Add(new ClientFloorRefusal(presented, now, reason));
            if (_refusals.Count > MaxRefusals) _refusals.RemoveRange(0, _refusals.Count - MaxRefusals);
        }
    }
}

// ------------------------------------------- HS-06 legacy PAK purge + HS-07

public sealed record HubNodeRecord(
    string NodeId, string DeviceId, string TailscaleVersion,
    DateTimeOffset JoinedUtc, bool Deleted,
    // BD-SHARED-TRANSPORT F2: Headscale's OWN numeric node id for
    // this device, learned from the hub (nodes list / join
    // response) via RecordHeadscaleNodeId. The DeskGuest NodeId above
    // is a local mirror key — Headscale does not know it, and the
    // HS-07 delete command must name the numeric id.
    string? HeadscaleNodeId = null,
    // Set when the device was decommissioned (via reconcile)
    // before its numeric id was known: the local delete stands,
    // the hub-side delete is OWED and is produced by
    // RecordHeadscaleNodeId when the sync learns the id.
    bool HubDeletePending = false);

/// <summary>The DeskGuest-side node registry mirroring hub membership. Join goes
/// through the client floor; decommission DELETES the node (HS-07 — expiring
/// a key does not decommission, because re-registration skips key
/// validation). A deleted node that tries to reconnect is refused here and
/// the refusal is recorded.</summary>
public sealed class HubNodeRegistry
{
    private readonly ClientVersionGate _floor;
    private readonly Dictionary<string, HubNodeRecord> _byDevice = new();
    private readonly List<string> _events = new();
    private readonly object _gate = new();

    public HubNodeRegistry(ClientVersionGate floor) => _floor = floor;

    /// <summary>BD-SHARED-TRANSPORT F12: registry events are a
    /// bounded ring (512).</summary>
    public const int MaxEvents = 512;

    public IReadOnlyList<string> Events { get { lock (_gate) return _events.ToList(); } }

    private void AddEvent(string entry)
    {
        _events.Add(entry);
        if (_events.Count > MaxEvents) _events.RemoveRange(0, _events.Count - MaxEvents);
    }

    /// <summary>Admits a device to the hub. Returns the assigned node id, or
    /// null (with the refusal recorded in the gate / event log).</summary>
    public string? Join(string deviceId, string tailscaleVersion, DateTimeOffset now)
    {
        if (!_floor.Admit(tailscaleVersion, now))
        {
            lock (_gate) AddEvent($"{now:O} join-refused device={deviceId} client={tailscaleVersion} reason=client-floor");
            return null;
        }
        lock (_gate)
        {
            if (_byDevice.TryGetValue(deviceId, out var existing) && existing.Deleted)
            {
                AddEvent($"{now:O} join-refused device={deviceId} reason=decommissioned-node-deleted");
                return null;
            }
            var nodeId = "node-" + Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(deviceId)))[..12].ToLowerInvariant();
            _byDevice[deviceId] = new HubNodeRecord(nodeId, deviceId, tailscaleVersion, now, Deleted: false);
            AddEvent($"{now:O} joined device={deviceId} node={nodeId} client={tailscaleVersion}");
            return nodeId;
        }
    }

    /// <summary>BD-SHARED-TRANSPORT F2: record Headscale's own
    /// numeric node id for a joined device (learned from the hub's
    /// node list). Until this is recorded, Decommission refuses
    /// to emit a delete command — the DeskGuest-hashed id is not an
    /// identifier Headscale accepts, and a command that would be
    /// rejected must not be dressed up as the HS-07 guarantee.</summary>
    public string? RecordHeadscaleNodeId(string deviceId, string headscaleNodeId)
    {
        if (string.IsNullOrWhiteSpace(headscaleNodeId) || !headscaleNodeId.All(char.IsDigit))
            throw new ArgumentException("Headscale node ids are numeric.", nameof(headscaleNodeId));
        lock (_gate)
        {
            if (!_byDevice.TryGetValue(deviceId, out var rec))
                throw new InvalidOperationException($"device {deviceId} has no hub node to annotate");
            _byDevice[deviceId] = rec with { HeadscaleNodeId = headscaleNodeId, HubDeletePending = false };
            // A device reconcile-decommissioned before its id was
            // known is owed this delete: produce the command now
            // for the caller to execute (late, never fabricated).
            return rec.HubDeletePending
                ? $"headscale nodes delete --identifier {headscaleNodeId}"
                : null;
        }
    }

    /// <summary>Devices decommissioned locally whose hub-side
    /// delete is still owed because the numeric node id was not
    /// yet known. Empty in the steady state; non-empty is an
    /// operator-visible backlog, never a silent leak.</summary>
    public IReadOnlyList<string> PendingHubDeletions()
    {
        lock (_gate)
            return _byDevice.Values.Where(r => r.HubDeletePending)
                .Select(r => r.DeviceId).ToList();
    }

    /// <summary>Decommission (HS-07): DELETE the node. Returns the hub admin
    /// command the lifecycle must execute against Headscale; expiring keys
    /// is never accepted as a substitute. BD-SHARED-TRANSPORT F2:
    /// the command names Headscale's numeric node id; when that id
    /// was never learned from the hub, this REFUSES instead of
    /// emitting a command Headscale would reject.</summary>
    public string Decommission(string deviceId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_byDevice.TryGetValue(deviceId, out var rec))
                throw new InvalidOperationException($"device {deviceId} has no hub node to delete");
            if (rec.HeadscaleNodeId is null)
                throw new InvalidOperationException(
                    $"device {deviceId}: Headscale's numeric node id is not recorded — the HS-07 delete cannot be issued against the DeskGuest-local id; sync the node list from the hub first (RecordHeadscaleNodeId)");
            _byDevice[deviceId] = rec with { Deleted = true };
            AddEvent($"{now:O} decommissioned device={deviceId} node={rec.NodeId} action=delete-node");
            return $"headscale nodes delete --identifier {rec.HeadscaleNodeId}";
        }
    }

    /// <summary>BD-SHARED-TRANSPORT F12: the admin re-enrol path.
    /// A decommissioned (Deleted) device could previously never
    /// rejoin — Join refused it forever. Reenroll clears the
    /// Deleted flag through the SAME join gate (client floor +
    /// fresh admission), and records the act as its own event so
    /// the resurrection is auditable, never silent.</summary>
    public string? Reenroll(string deviceId, string tailscaleVersion, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_byDevice.TryGetValue(deviceId, out var existing) || !existing.Deleted)
                return Join(deviceId, tailscaleVersion, now);
            _byDevice[deviceId] = existing with { Deleted = false };
            AddEvent($"{now:O} reenroll-cleared device={deviceId} — decommission flag cleared by admin re-enrol; fresh join follows");
        }
        return Join(deviceId, tailscaleVersion, now);
    }

    public HubNodeRecord? Get(string deviceId)
    {
        lock (_gate) return _byDevice.TryGetValue(deviceId, out var r) ? r : null;
    }

    /// <summary>Offboarding reconciliation (HS-07 wired into DeskGuest's
    /// device-delete path): every hub node whose device is no longer in the
    /// live device set is DELETED here. Returns the hub admin commands to
    /// execute. Called by the Core whenever the enrollment roster changes,
    /// so removing a device from DeskGuest removes its hub node — never merely
    /// expiring a key.</summary>
    public IReadOnlyList<string> ReconcileDeletions(IReadOnlySet<string> liveDeviceIds, DateTimeOffset now)
    {
        var commands = new List<string>();
        List<string> orphans;
        lock (_gate)
            orphans = _byDevice.Values.Where(r => !r.Deleted && !liveDeviceIds.Contains(r.DeviceId))
                .Select(r => r.DeviceId).ToList();
        foreach (var deviceId in orphans)
        {
            HubNodeRecord? rec;
            lock (_gate) _byDevice.TryGetValue(deviceId, out rec);
            if (rec?.HeadscaleNodeId is not null)
            {
                commands.Add(Decommission(deviceId, now));
                continue;
            }
            // The numeric id is not synced yet: the local
            // decommission still happens (the device IS gone),
            // but NO delete command is fabricated — the record is
            // flagged HubDeletePending and the delete command is
            // produced by RecordHeadscaleNodeId when the sync
            // learns the id. Direct Decommission() callers get the
            // throw instead: they asked for the delete itself.
            lock (_gate)
            {
                if (_byDevice.TryGetValue(deviceId, out var r) && !r.Deleted)
                {
                    _byDevice[deviceId] = r with { Deleted = true, HubDeletePending = true };
                    AddEvent($"hub_delete_pending:{deviceId}");
                }
            }
        }
        return commands;
    }

    /// <summary>HS-06: scans a pre-auth-key store export (JSON array, the
    /// Headscale DB shape) and purges every entry still carrying a legacy
    /// PLAINTEXT `key` column. Bcrypt-era entries carry only prefix+hash and
    /// are kept. Returns the cleaned export and the purged key ids.</summary>
    public static (string CleanedJson, IReadOnlyList<string> PurgedIds) PurgeLegacyPlaintextPreAuthKeys(string exportJson)
    {
        var purged = new List<string>();
        var kept = new List<JsonElement>();
        using var doc = JsonDocument.Parse(exportJson);
        foreach (var el in doc.RootElement.EnumerateArray())
        {
            var hasPlaintext = el.TryGetProperty("key", out var k)
                && k.ValueKind == JsonValueKind.String
                && !string.IsNullOrEmpty(k.GetString());
            if (hasPlaintext)
            {
                purged.Add(el.TryGetProperty("id", out var id) ? id.ToString() : "(unknown id)");
                continue;
            }
            kept.Add(el.Clone());
        }
        var sb = new StringBuilder("[");
        for (var i = 0; i < kept.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(kept[i].GetRawText());
        }
        sb.Append(']');
        return (sb.ToString(), purged);
    }
}

// ------------------------------------------------------------ D28 join flow

public sealed record HubJoinTicket(
    string DeviceId, string GroupId, string LoginServer,
    string CommandLine, DateTimeOffset ExpiresUtc);

/// <summary>Guided join (D28/D7/D3): DeskGuest mints a single-use, ≤1 h pre-auth
/// key under the hood (group pre-authorization: enrolling into the group IS
/// the authorization) and produces the exact client command the endpoint's
/// agent applies itself. The endpoint never sees an account or a sign-in.
/// The key plaintext is protector-wrapped at rest and consumed on use.</summary>
public sealed class HubJoinService
{
    private sealed class PakEntry
    {
        public required string ProtectedKey { get; init; }
        public required string DeviceId { get; init; }
        public required string GroupId { get; init; }
        public required DateTimeOffset ExpiresUtc { get; init; }
        public bool Used { get; set; }
    }

    private readonly ISecretProtector _protector;
    private readonly HubNodeRegistry _registry;
    private readonly IHeadscaleKeyAuthority? _authority;
    private readonly string _hubUser;
    private readonly Dictionary<string, PakEntry> _paks = new();
    private readonly object _gate = new();

    /// <param name="authority">BD-SHARED-TRANSPORT F2: the
    /// Headscale key authority — MintJoinTicket's key is issued
    /// by Headscale (preauthkeys create), not invented locally.
    /// Null ⇒ minting refuses (fail closed).</param>
    public HubJoinService(ISecretProtector protector, HubNodeRegistry registry,
        IHeadscaleKeyAuthority? authority = null, string hubUser = "deskguest")
    {
        _protector = protector;
        _registry = registry;
        _authority = authority;
        _hubUser = hubUser;
    }

    /// <summary>BD-SHARED-TRANSPORT F12: expired/used PAKs are
    /// pruned on every mint/consume — the store previously grew
    /// forever on a long-running hub.</summary>
    private void PrunePaks(DateTimeOffset now)
    {
        var dead = _paks.Where(kv => kv.Value.Used || now >= kv.Value.ExpiresUtc)
            .Select(kv => kv.Key).ToList();
        foreach (var k in dead) _paks.Remove(k);
    }

    public HubJoinTicket MintJoinTicket(string deviceId, string groupId, string serverUrl, DateTimeOffset now)
    {
        // BD-SHARED-TRANSPORT F2: the key is issued by Headscale
        // itself; DeskGuest never invents one in its format.
        var keyPlain = _authority?.CreatePreAuthKey(_hubUser, HubPins.MaxPreAuthKeyLifetime)
            ?? throw new InvalidOperationException(
                "no Headscale key authority wired — DeskGuest cannot mint a hub pre-auth key locally; keys are issued by Headscale itself (preauthkeys create) and only consumed here");
        var entry = new PakEntry
        {
            ProtectedKey = _protector.Protect(keyPlain),
            DeviceId = deviceId,
            GroupId = groupId,
            ExpiresUtc = now + HubPins.MaxPreAuthKeyLifetime,
        };
        lock (_gate) { PrunePaks(now); _paks[keyPlain[..Math.Min(21, keyPlain.Length)]] = entry; } // lookup by prefix, like Headscale
        return new HubJoinTicket(
            deviceId, groupId, serverUrl,
            $"tailscale up --login-server {serverUrl} --authkey {keyPlain} --accept-routes=false",
            entry.ExpiresUtc);
    }

    /// <summary>Consumes a presented pre-auth key for a joining device.
    /// Single-use and expiry are enforced atomically; the join then passes
    /// through the registry (client floor + decommission checks).</summary>
    public string? ConsumeJoin(string presentedKey, string deviceId, string tailscaleVersion, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(presentedKey) || presentedKey.Length < 8) return null;
        var prefix = presentedKey[..Math.Min(21, presentedKey.Length)];
        lock (_gate)
        {
            PrunePaks(now);
            if (!_paks.TryGetValue(prefix, out var e)) return null;
            if (e.Used || now >= e.ExpiresUtc) return null;
            if (!string.Equals(_protector.Unprotect(e.ProtectedKey), presentedKey, StringComparison.Ordinal)) return null;
            if (e.DeviceId != deviceId) return null;
            e.Used = true; // consumed even if the floor refuses — a burned key stays burned
        }
        return _registry.Join(deviceId, tailscaleVersion, now);
    }
}

// ------------------------------------------------------------- hub lifecycle

public interface IHubProcess
{
    bool IsRunning { get; }
    void Start(string binaryPath, string configPath, string workingDir);
    void Stop();
    bool HealthOk(string healthUrl);
}

public enum HubState { NotInstalled, Installed, Running, Stopped, Refused }

/// <summary>The DeskGuest lifecycle for the hub component (D16/D27): install /
/// start / stop / update under DeskGuest's control, data in DeskGuest-managed storage,
/// and NOTHING runs unless a scope chose the hub rung. Start re-reads the
/// on-disk config + policy and runs the §8 self-check every time — a
/// hand-edited file can only ever make the hub refuse, never weaken it
/// silently: on refusal the lifecycle RE-ASSERTS DeskGuest's generated config and
/// deny-by-default policy, then refuses that start (the next start is clean).</summary>
public sealed class HubLifecycle
{
    private readonly HubOptions _options;
    private readonly IHubProcess _process;
    private readonly bool _hubRungSelected;

    public HubState State { get; private set; } = HubState.NotInstalled;
    public string? LastRefusal { get; private set; }

    public HubLifecycle(HubOptions options, IHubProcess process, bool hubRungSelected)
    {
        _options = options;
        _process = process;
        _hubRungSelected = hubRungSelected;
    }

    /// <summary>True when a BinarySha256 pin is configured AND
    /// the on-disk binary matches it. False both when the pin is
    /// absent (unverifiable — surfaced, never silently passed) and
    /// when it mismatches; VerifyBinary distinguishes the two.</summary>
    public bool BinaryVerified => _options.BinarySha256 is not null && VerifyBinary() is null;

    /// <summary>BD-SHARED-TRANSPORT F11: verify the hub binary
    /// against the per-platform pinned hash. Returns null when
    /// verified, otherwise the refusal reason. The previously
    /// pinned OfficialLinuxAmd64Sha256 was never checked anywhere
    /// and no Windows pin existed; the pin now travels in
    /// HubOptions.BinarySha256 (recorded by packaging for the
    /// platform being installed) and is enforced here.</summary>
    public string? VerifyBinary()
    {
        if (!File.Exists(_options.BinaryPath)) return "hub binary missing";
        if (_options.BinarySha256 is null)
            return "no BinarySha256 pin configured for this platform — the hub binary cannot be verified (packaging must record the rebuilt binary's hash)";
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_options.BinaryPath))).ToLowerInvariant();
        return string.Equals(actual, _options.BinarySha256.Trim().ToLowerInvariant(), StringComparison.Ordinal)
            ? null
            : $"hub binary hash mismatch: expected {_options.BinarySha256}, actual {actual} — refused (a swapped hub binary is a swapped control plane)";
    }

    /// <summary>Install = lay down the component home: generated config +
    /// deny-by-default policy + data dir. The binary itself is placed by the
    /// packaging step (hash-pinned); Install verifies it exists and, when a
    /// pin is configured, that it MATCHES (F11).</summary>
    public void Install()
    {
        Directory.CreateDirectory(_options.ComponentHome);
        Directory.CreateDirectory(_options.DataDir);
        if (!File.Exists(_options.BinaryPath))
            throw new FileNotFoundException(
                "hub binary missing — packaging places the pinned, hash-verified binary first", _options.BinaryPath);
        if (_options.BinarySha256 is not null && VerifyBinary() is { } mismatch)
            throw new InvalidOperationException(mismatch);
        File.WriteAllText(_options.ConfigPath, HubConfig.Generate(_options));
        File.WriteAllText(_options.PolicyPath, HubPolicy.DenyByDefault);
        State = HubState.Installed;
    }

    public void Start()
    {
        if (!_hubRungSelected)
            throw new InvalidOperationException(
                "D16: the hub is an option, not a mandate — no scope chose the hub rung, so the hub does not run");
        if (State is HubState.NotInstalled) Install();

        // Self-check against the files AS THEY EXIST ON DISK (§8.3).
        var configText = File.ReadAllText(_options.ConfigPath);
        var policyText = File.ReadAllText(_options.PolicyPath);
        var violations = HubStartupSelfCheck.Check(configText, policyText, _options);
        if (violations.Count > 0)
        {
            // Re-assert DeskGuest's artefacts so the tamper cannot persist, then
            // refuse THIS start.
            File.WriteAllText(_options.ConfigPath, HubConfig.Generate(_options));
            File.WriteAllText(_options.PolicyPath, HubPolicy.DenyByDefault);
            State = HubState.Refused;
            LastRefusal = string.Join("; ", violations.Select(v => v.Condition + " — " + v.Detail));
            throw new HubRefusalException(violations);
        }
        if (_options.BinarySha256 is not null && VerifyBinary() is { } mismatch)
        {
            State = HubState.Refused;
            LastRefusal = mismatch;
            throw new InvalidOperationException(mismatch);
        }
        _process.Start(_options.BinaryPath, _options.ConfigPath, _options.ComponentHome);
        // BD-SHARED-TRANSPORT F11: Running is a HEALTH verdict,
        // not a hope — the process starting is not the hub
        // serving. Poll HealthOk under a deadline; a hub that
        // crashes on launch lands in Refused with the reason, and
        // the process is stopped again.
        var healthUrl = _options.ServerUrl.TrimEnd('/') + "/health";
        var deadline = DateTimeOffset.UtcNow + HealthDeadline;
        var healthy = false;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (!_process.IsRunning) break;
            try { healthy = _process.HealthOk(healthUrl); } catch { healthy = false; }
            if (healthy) break;
            System.Threading.Thread.Sleep(100);
        }
        if (!healthy)
        {
            try { _process.Stop(); } catch { /* already dead */ }
            State = HubState.Refused;
            LastRefusal = "hub process started but did not report healthy at " + healthUrl +
                " within " + HealthDeadline + " — treated as crashed-on-launch, not Running";
            throw new InvalidOperationException(LastRefusal);
        }
        State = HubState.Running;
    }

    /// <summary>How long Start waits for the hub to report
    /// healthy before calling it crashed-on-launch (F11).</summary>
    public static readonly TimeSpan HealthDeadline = TimeSpan.FromSeconds(10);

    public void Stop()
    {
        if (_process.IsRunning) _process.Stop();
        if (State == HubState.Running) State = HubState.Stopped;
    }

    /// <summary>Update = replace the binary ONLY at the pinned version stamp
    /// (a version bump needs its delta audit first, §8.1/D37 — the caller
    /// must present the audit stamp for any other version, and this method
    /// records the refusal otherwise).
    /// BD-SHARED-TRANSPORT F11: Update previously did NOTHING
    /// after the gate — no swap, no hash check. With a candidate
    /// binary path it now performs the real act: verify the
    /// candidate against the pin (when configured), swap it in
    /// atomically with the previous binary kept as .prev for
    /// rollback, and restore the old binary if the swap fails
    /// mid-way. Without a candidate path it remains a gate-only
    /// call and says so in its return.</summary>
    public string Update(string candidateVersion, string? deltaAuditStamp, string? candidateBinaryPath = null)
    {
        if (candidateVersion != HubPins.HeadscaleVersion && string.IsNullOrWhiteSpace(deltaAuditStamp))
            throw new InvalidOperationException(
                $"hub update to {candidateVersion} refused: version bumps require a delta audit (D37/§8.1); pinned version is {HubPins.HeadscaleVersion}");
        if (candidateBinaryPath is null)
            return "gate passed; no candidate binary supplied — nothing was swapped (Update replaces the binary only when a candidate path is presented)";
        if (!File.Exists(candidateBinaryPath))
            throw new FileNotFoundException("candidate hub binary missing", candidateBinaryPath);
        if (_options.BinarySha256 is not null)
        {
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(candidateBinaryPath))).ToLowerInvariant();
            if (!string.Equals(actual, _options.BinarySha256.Trim().ToLowerInvariant(), StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"candidate hub binary hash mismatch: expected {_options.BinarySha256}, actual {actual} — update refused, installed binary untouched");
        }
        var wasRunning = _process.IsRunning;
        if (wasRunning) _process.Stop();
        var prev = _options.BinaryPath + ".prev";
        try
        {
            if (File.Exists(_options.BinaryPath)) File.Copy(_options.BinaryPath, prev, overwrite: true);
            File.Copy(candidateBinaryPath, _options.BinaryPath, overwrite: true);
        }
        catch
        {
            if (File.Exists(prev)) File.Copy(prev, _options.BinaryPath, overwrite: true);
            throw;
        }
        return $"hub binary replaced with the {candidateVersion} candidate (previous kept at {prev} for rollback)" +
               (wasRunning ? "; the hub was stopped for the swap and must be started again" : "");
    }
}
