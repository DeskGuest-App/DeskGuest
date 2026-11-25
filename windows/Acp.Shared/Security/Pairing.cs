using System.Security.Cryptography;
using System.Text.Json;

namespace Acp.Shared.Security;

/// <summary>A pairing: one agent's grant on this host (SPEC §5.2, DESIGN §6.2).
/// Created on the laptop only; the bearer token is issued once, at exchange.</summary>
public sealed record Pairing(
    string Id,
    string AgentName,
    IReadOnlySet<string> Scopes,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ExpiresUtc,
    TimeSpan? SessionTimeBox,
    bool Revoked,
    // W97 / S09(b): the pairing's connection-path setting (mode +
    // subset/pin). Null = a pre-W97 record — its effective setting
    // is AUTO (the pre-policy behavior), never a silent restriction.
    ConnectionPathSetting? Connection = null,
    // W107 (W106-verified C5): present-but-corrupt quarantine. When
    // a stored record HAS connection fields but they fail
    // parse/validation, the restore is fail-CLOSED (see
    // ConnectionFromStore): ConnectionCorrupt is set, the ORIGINAL
    // stored fields are carried verbatim in the Corrupt* fields so
    // ExportJson writes them back untouched (never silently
    // overwritten with AUTO), and EffectiveConnection refuses every
    // rung until the owner re-sets the path (UpdateConnectionPath
    // clears the quarantine). Missing fields entirely (the genuine
    // pre-W97 migration) never set this — that case stays AUTO.
    bool ConnectionCorrupt = false,
    string? CorruptConnectionMode = null,
    string[]? CorruptConnectionRungs = null,
    string? CorruptConnectionPin = null,
    // FR-134 / item (16): the Terms acknowledgment this pairing has
    // on record — the version + SHA-256 of the exact Terms text the
    // agent client acknowledged, and when. All three null = the
    // agent has never acknowledged (every pre-FR-134 record, and
    // every fresh pairing until its client acks): such a pairing
    // is session-locked until it acks the CURRENT Terms hash.
    string? TermsAckVersion = null,
    string? TermsAckHash = null,
    DateTimeOffset? TermsAckUtc = null)
{
    /// <summary>FR-134: true when this pairing's recorded Terms
    /// acknowledgment names exactly the hash the host currently
    /// serves — the one state in which sessions may start. A null
    /// ack, or an ack of any older text, is not current: a Terms
    /// update re-locks the pairing until it re-acknowledges.</summary>
    public bool HasCurrentTermsAck(string currentTermsSha256) =>
        TermsAckHash is not null &&
        string.Equals(TermsAckHash, currentTermsSha256, StringComparison.Ordinal);
    /// <summary>The setting enforcement reads: the stored one, or
    /// AUTO for a record that predates the policy — or, W107, the
    /// fail-closed CorruptRefused setting for a present-but-corrupt
    /// record, which no rung satisfies.</summary>
    public ConnectionPathSetting EffectiveConnection =>
        ConnectionCorrupt
            ? ConnectionPathSetting.CorruptRefusedSetting
            : Connection ?? ConnectionPathSetting.DefaultAuto;

    /// <summary>W107: true when this pairing's stored connection
    /// setting was present but unreadable — the agent card shows
    /// the setting needs attention; it never claims AUTO.</summary>
    public bool ConnectionNeedsAttention => ConnectionCorrupt;
}

/// <summary>Result of a successful one-time-code exchange.</summary>
public sealed record PairingExchange(string PairingId, string BearerToken);

/// <summary>
/// Pairing lifecycle: one-time codes are minted on the host (laptop UI /
/// installer bootstrap) WITH their granted scopes bound at mint time —
/// the exchanging caller can never choose or widen its own privilege
/// (second-inspector finding C1). Codes are presented exactly once and
/// exchanged for a per-pairing bearer token. Only a SHA-256 hash of the
/// token is kept, so the store file never contains a usable token; the
/// ISecretProtector protects the recorded agent name at rest.
/// Revocation takes effect on the next authentication check — i.e. the
/// next tool call (SPEC §5.2).
/// </summary>
public sealed class PairingService
{
    private sealed record StoredPairing(
        Pairing Pairing,
        string TokenHash,
        string ProtectedAgentName);

    private sealed record PendingCode(string Code, DateTimeOffset ExpiresUtc, string IntendedAgentName, IReadOnlySet<string> GrantedScopes, ConnectionPathSetting Connection);

    private readonly Dictionary<string, StoredPairing> _pairings = new();
    private readonly Dictionary<string, PendingCode> _pending = new();
    // W97: the rung each pairing was LAST seen authenticated on,
    // with when — live state of THIS run only (never persisted:
    // a stored claim about "current path" would be a lie after a
    // restart). The agent card's current-rung label reads this.
    private readonly Dictionary<string, (string Rung, DateTimeOffset AtUtc)> _lastConnection = new();
    private readonly ISecretProtector _protector;
    private readonly object _gate = new();

    public PairingService(ISecretProtector protector) => _protector = protector;

    public ISecretProtector Protector => _protector;

    /// <summary>Raised after any durable mutation (exchange, revoke) so
    /// the host can persist the store. Pairings MUST survive a Core
    /// restart — re-pairing after every service restart would break the
    /// always-on contract this product exists to keep.</summary>
    public event Action? Changed;

    /// <summary>Mint a one-time pairing code (host-side action only).
    /// The granted scopes are BOUND TO THE CODE here, on the host; the
    /// exchange can only ever receive what the host intended. Default
    /// when unspecified is the least-privilege look-only preset.</summary>
    public string CreatePairingCode(string intendedAgentName, TimeSpan ttl, IReadOnlySet<string>? grantedScopes = null,
        ConnectionPathSetting? connection = null)
    {
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)); // 64-bit code, shown on the laptop
        lock (_gate)
        {
            // W97: the connection-path setting is bound at mint too
            // (the C1 rule applied to the path dimension): the
            // exchanging caller can no more choose its path policy
            // than its scopes. An invalid owner-supplied setting
            // falls back to AUTO only when it is absent — a supplied
            // but invalid one refuses the mint by throwing, so the
            // Core surfaces the refusal instead of silently widening.
            var bound = connection ?? ConnectionPathSetting.DefaultAuto;
            if (ConnectionPathPolicy.Validate(bound) is { } refusal)
                throw new ArgumentException(refusal, nameof(connection));
            _pending[code] = new PendingCode(code, DateTimeOffset.UtcNow + ttl, intendedAgentName,
                grantedScopes ?? Scopes.Preset("look_only"), bound);
        }
        return code;
    }

    /// <summary>W97: the connection setting bound to a pending
    /// code, WITHOUT consuming it — the exchange door checks the
    /// arrival lane against it before the exchange runs (a refusal
    /// leaves the code alive for its allowed path). Null when the
    /// code is unknown or expired.</summary>
    public ConnectionPathSetting? PeekCodeConnection(string code)
    {
        lock (_gate)
        {
            if (!_pending.TryGetValue(code, out var pending)) return null;
            if (DateTimeOffset.UtcNow > pending.ExpiresUtc) return null;
            return pending.Connection;
        }
    }

    /// <summary>Exchange a one-time code for a pairing + bearer token.
    /// The pairing's AgentName is the HOST-INTENDED name bound to
    /// the code at mint time — never the exchanging client's
    /// self-report (Block H D38 fix F3, the C1 rule applied to
    /// identity: just as the caller cannot choose its scopes, it
    /// cannot choose its name). Before this fix the client's
    /// claimed name became the pairing's identity, and Block G's
    /// roster resolution matched roster AI users by that name —
    /// a paired agent could name itself after any roster AI user
    /// and act with that user's 'use' grants. The self-reported
    /// <paramref name="agentName"/> is kept in the handler's audit
    /// trail as a claim; it decides nothing.</summary>
    public PairingExchange? ExchangeCode(string code, string agentName, DateTimeOffset? expiresUtc = null, TimeSpan? sessionTimeBox = null)
    {
        lock (_gate)
        {
            if (!_pending.TryGetValue(code, out var pending)) return null;
            _pending.Remove(code); // one-time: consumed whether it succeeds or not from here
            if (DateTimeOffset.UtcNow > pending.ExpiresUtc) return null;

            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var pairing = new Pairing(
                Id: Guid.NewGuid().ToString("N"),
                AgentName: pending.IntendedAgentName,
                Scopes: pending.GrantedScopes,
                CreatedUtc: DateTimeOffset.UtcNow,
                ExpiresUtc: expiresUtc,
                SessionTimeBox: sessionTimeBox,
                Revoked: false,
                Connection: pending.Connection);
            _pairings[pairing.Id] = new StoredPairing(pairing, Hash(token), _protector.Protect(pairing.AgentName));
            Changed?.Invoke();
            return new PairingExchange(pairing.Id, token);
        }
    }

    /// <summary>Authenticate a bearer token. Fails closed: unknown, revoked,
    /// or expired pairings all return null.</summary>
    public Pairing? Authenticate(string? bearerToken)
    {
        if (string.IsNullOrWhiteSpace(bearerToken)) return null;
        var hash = Hash(bearerToken);
        var hashBytes = Convert.FromHexString(hash);
        lock (_gate)
        {
            foreach (var stored in _pairings.Values)
            {
                byte[] storedBytes;
                try { storedBytes = Convert.FromHexString(stored.TokenHash); }
                catch (FormatException) { continue; } // a corrupt entry must not brick everyone else (M8)
                if (!CryptographicOperations.FixedTimeEquals(storedBytes, hashBytes))
                    continue;
                var p = stored.Pairing;
                if (p.Revoked) return null;
                if (p.ExpiresUtc is { } exp && DateTimeOffset.UtcNow > exp) return null;
                return p;
            }
        }
        return null;
    }

    /// <summary>W79 / S08: replace a pairing's grant set — the
    /// access-control surface's ONE write. Host-side only (the
    /// Core calls it from the authenticated laptop-UI channel;
    /// there is no tool/HTTP path). The proposal is validated by
    /// <see cref="AccessControl.ValidateProposal"/>: unknown
    /// grants refuse, and ADDING the elevation class refuses
    /// without the owner's separate confirmation. A revoked or
    /// unknown pairing refuses. On success the new set is the
    /// pairing's enforcement state from the next authentication
    /// check, and Changed persists the store. Returns
    /// (ok, detail, oldScopes) so the caller can audit exactly
    /// what changed.</summary>
    public (bool Ok, string Detail, IReadOnlySet<string>? OldScopes) UpdateScopes(
        string pairingId, IReadOnlySet<string> proposed, bool elevationConfirmed)
    {
        lock (_gate)
        {
            if (!_pairings.TryGetValue(pairingId, out var stored))
                return (false, "unknown pairing — refused", null);
            if (stored.Pairing.Revoked)
                return (false, "pairing is revoked — refused", null);
            var current = stored.Pairing.Scopes;
            if (AccessControl.ValidateProposal(current, proposed, elevationConfirmed) is { } refusal)
                return (false, refusal, null);
            var next = new HashSet<string>(proposed);
            _pairings[pairingId] = stored with { Pairing = stored.Pairing with { Scopes = next } };
            Changed?.Invoke();
            return (true, "grants updated", current);
        }
    }

    /// <summary>W97 / S09(b): replace a pairing's connection-path
    /// setting — the agent card's ONE connection write. Host-side
    /// only (the Core calls it from the authenticated laptop-UI
    /// channel; there is no tool/HTTP path). The proposal is
    /// validated by <see cref="ConnectionPathPolicy.Validate"/>:
    /// unknown rungs, an empty restricted subset, and a manual
    /// mode without a pin all refuse. A revoked or unknown
    /// pairing refuses. On success the new setting is the
    /// pairing's enforcement state from the next authenticated
    /// connection, and Changed persists the store. Returns
    /// (ok, detail, oldSetting) so the caller can audit exactly
    /// what changed.</summary>
    public (bool Ok, string Detail, ConnectionPathSetting? OldSetting) UpdateConnectionPath(
        string pairingId, ConnectionPathSetting proposed)
    {
        lock (_gate)
        {
            if (!_pairings.TryGetValue(pairingId, out var stored))
                return (false, "unknown pairing — refused", null);
            if (stored.Pairing.Revoked)
                return (false, "pairing is revoked — refused", null);
            if (ConnectionPathPolicy.Validate(proposed) is { } refusal)
                return (false, refusal, null);
            var current = stored.Pairing.EffectiveConnection;
            var normalized = new ConnectionPathSetting(
                proposed.Mode,
                proposed.Mode == ConnectionMode.AutoRestricted ? proposed.AllowedOrEmpty : null,
                proposed.Mode == ConnectionMode.Manual ? proposed.PinOrNull : null);
            // W107: an owner's successful re-set is the repair for a
            // quarantined corrupt record — the quarantine and its
            // preserved original fields are cleared here, and only
            // here (never by an export, never silently).
            _pairings[pairingId] = stored with
            {
                Pairing = stored.Pairing with
                {
                    Connection = normalized,
                    ConnectionCorrupt = false,
                    CorruptConnectionMode = null,
                    CorruptConnectionRungs = null,
                    CorruptConnectionPin = null,
                }
            };
            Changed?.Invoke();
            return (true, "connection path updated", current);
        }
    }

    /// <summary>W107: the pairing's CURRENT stored record by id —
    /// the event-stream leg's mid-stream re-check reads this (the
    /// record Authenticate returned at attach is an immutable
    /// snapshot; a restriction the owner lands mid-stream lives
    /// only in the store's current record). Fails closed exactly
    /// like Authenticate: unknown, revoked, or expired → null.</summary>
    public Pairing? CurrentPairing(string pairingId)
    {
        lock (_gate)
        {
            if (!_pairings.TryGetValue(pairingId, out var stored)) return null;
            var p = stored.Pairing;
            if (p.Revoked) return null;
            if (p.ExpiresUtc is { } exp && DateTimeOffset.UtcNow > exp) return null;
            return p;
        }
    }

    /// <summary>W97: record that this pairing authenticated over
    /// <paramref name="rungId"/> just now — the live fact behind
    /// the card's "actually on" label. Called by the connection
    /// choke point ONLY after the path policy allowed the arrival;
    /// a refused arrival never moves the label.</summary>
    public void NoteConnection(string pairingId, string rungId)
    {
        var rung = ConnectionPathSetting.NormalizeRung(rungId);
        if (rung.Length == 0) return;
        lock (_gate) _lastConnection[pairingId] = (rung, DateTimeOffset.UtcNow);
    }

    /// <summary>The pairing's last authenticated rung this run,
    /// or null when it has not connected since the Core started.</summary>
    public (string Rung, DateTimeOffset AtUtc)? LastConnection(string pairingId)
    {
        lock (_gate)
            return _lastConnection.TryGetValue(pairingId, out var seen) ? seen : null;
    }

    public bool Revoke(string pairingId)
    {
        lock (_gate)
        {
            if (!_pairings.TryGetValue(pairingId, out var stored)) return false;
            _pairings[pairingId] = stored with { Pairing = stored.Pairing with { Revoked = true } };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>FR-134 / item (16): record this pairing's protocol
    /// acknowledgment of the Terms — the exact version + SHA-256
    /// the agent client returned, stamped with the host's clock.
    /// Called by the MCP layer ONLY after it has verified the
    /// returned hash equals the currently served Terms hash (a
    /// wrong-hash ack never reaches this method). A revoked or
    /// unknown pairing refuses: a dead pairing cannot sign for
    /// anything. On success the record is the pairing's standing
    /// Terms state from the next check, and Changed persists the
    /// store — the acknowledgment must survive a Core restart
    /// exactly like the pairing itself does.</summary>
    public (bool Ok, DateTimeOffset? AckUtc) RecordTermsAck(string pairingId, string termsVersion, string termsSha256)
    {
        lock (_gate)
        {
            if (!_pairings.TryGetValue(pairingId, out var stored)) return (false, null);
            if (stored.Pairing.Revoked) return (false, null);
            var at = DateTimeOffset.UtcNow;
            _pairings[pairingId] = stored with
            {
                Pairing = stored.Pairing with
                {
                    TermsAckVersion = termsVersion,
                    TermsAckHash = termsSha256,
                    TermsAckUtc = at,
                }
            };
            Changed?.Invoke();
            return (true, at);
        }
    }

    public IReadOnlyList<Pairing> List()
    {
        lock (_gate) return _pairings.Values.Select(s => s.Pairing).ToList();
    }

    /// <summary>W107 rebuild of a stored connection setting — the
    /// MISSING and PRESENT-BUT-CORRUPT cases are split, because
    /// they are opposite in meaning:
    ///   * NO connection fields at all = the genuine pre-W97
    ///     migration: the record predates the policy, so AUTO is
    ///     its truth (unchanged from W97).
    ///   * Fields PRESENT but unparseable/invalid = corruption of
    ///     a setting the owner actually chose (pre-W107 this fell
    ///     through the same fallback and restored as AUTO — a
    ///     fail-open widening of a possibly-restricted pairing,
    ///     W106-verified C5). Now it restores FAIL-CLOSED: the
    ///     pairing carries the quarantine + the original fields
    ///     verbatim, EffectiveConnection refuses every rung, and
    ///     ExportJson writes the original fields back untouched
    ///     until the owner re-sets the path.
    /// A mode-less record that still carries rungs or a pin is
    /// present-but-corrupt, not a migration: its fields meant
    /// something and cannot be honored as written.</summary>
    private static (ConnectionPathSetting? Setting, bool Corrupt) ConnectionFromStore(
        string? mode, string[]? rungs, string? pin)
    {
        var anyFieldPresent = mode is not null || (rungs is not null && rungs.Length > 0) || pin is not null;
        if (!anyFieldPresent) return (null, false); // genuine migration → AUTO via EffectiveConnection
        if (mode is null) return (null, true);      // fields without a mode: corrupt
        var parsed = ConnectionPathPolicy.Parse(mode, rungs, pin);
        if (parsed is null || ConnectionPathPolicy.Validate(parsed) is not null)
            return (null, true);
        return (parsed, false);
    }

    private static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

    private sealed record StoredDto(
        string Id, string AgentName, string[] Scopes, DateTimeOffset CreatedUtc,
        DateTimeOffset? ExpiresUtc, double? SessionTimeBoxSeconds, bool Revoked,
        string TokenHash, string ProtectedAgentName,
        // W97: connection-path setting, defaulted so a pre-W97
        // store (which has none of these fields) restores as AUTO.
        string? ConnectionMode = null, string[]? ConnectionRungs = null, string? ConnectionPin = null,
        // FR-134: Terms acknowledgment, defaulted so a pre-FR-134
        // store (which has none of these fields) restores as
        // never-acknowledged — the pairing re-acks on its next
        // connection, exactly the item (16) update flow.
        string? TermsAckVersion = null, string? TermsAckHash = null, DateTimeOffset? TermsAckUtc = null);

    /// <summary>Restore a store previously produced by ExportJson.
    /// Malformed entries are skipped, never fatal: a corrupt store must
    /// not take the command plane down with it (the owner re-pairs).</summary>
    public int ImportJson(string json)
    {
        var dtos = JsonSerializer.Deserialize<StoredDto[]>(json) ?? Array.Empty<StoredDto>();
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in dtos)
            {
                // Validate before trusting: a malformed token hash would
                // otherwise poison Authenticate for every pairing (M8).
                if (string.IsNullOrWhiteSpace(dto.Id) || dto.TokenHash is null ||
                    dto.TokenHash.Length != 64 || !dto.TokenHash.All(Uri.IsHexDigit))
                    continue;
                var (restoredConnection, connectionCorrupt) =
                    ConnectionFromStore(dto.ConnectionMode, dto.ConnectionRungs, dto.ConnectionPin);
                var pairing = new Pairing(dto.Id, dto.AgentName,
                    new HashSet<string>(dto.Scopes), dto.CreatedUtc, dto.ExpiresUtc,
                    dto.SessionTimeBoxSeconds is { } secs ? TimeSpan.FromSeconds(secs) : null,
                    dto.Revoked,
                    restoredConnection,
                    // W107: quarantine carries the ORIGINAL stored
                    // fields verbatim (nulls included) so the export
                    // below reproduces the record exactly — the
                    // corruption is preserved for the owner to see
                    // and repair, never silently overwritten.
                    ConnectionCorrupt: connectionCorrupt,
                    CorruptConnectionMode: connectionCorrupt ? dto.ConnectionMode : null,
                    CorruptConnectionRungs: connectionCorrupt ? dto.ConnectionRungs : null,
                    CorruptConnectionPin: connectionCorrupt ? dto.ConnectionPin : null,
                    TermsAckVersion: dto.TermsAckVersion,
                    TermsAckHash: dto.TermsAckHash,
                    TermsAckUtc: dto.TermsAckUtc);
                _pairings[dto.Id] = new StoredPairing(pairing, dto.TokenHash, dto.ProtectedAgentName);
                restored++;
            }
        }
        return restored;
    }

    /// <summary>Serialize the store (token hashes only — never raw tokens).</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var dto = _pairings.Values.Select(s => new
            {
                s.Pairing.Id, s.Pairing.AgentName, Scopes = s.Pairing.Scopes.ToArray(),
                s.Pairing.CreatedUtc, s.Pairing.ExpiresUtc,
                SessionTimeBoxSeconds = s.Pairing.SessionTimeBox?.TotalSeconds,
                s.Pairing.Revoked, s.TokenHash, s.ProtectedAgentName,
                // W107: a quarantined corrupt record exports its
                // ORIGINAL fields verbatim — an export must never
                // launder corruption into a chosen-looking AUTO
                // (the pre-W107 permanence half of C5).
                ConnectionMode = s.Pairing.ConnectionCorrupt
                    ? s.Pairing.CorruptConnectionMode
                    : s.Pairing.EffectiveConnection.Mode.ToString(),
                ConnectionRungs = s.Pairing.ConnectionCorrupt
                    ? (s.Pairing.CorruptConnectionRungs ?? Array.Empty<string>())
                    : s.Pairing.EffectiveConnection.AllowedOrEmpty.OrderBy(r => r).ToArray(),
                ConnectionPin = s.Pairing.ConnectionCorrupt
                    ? s.Pairing.CorruptConnectionPin
                    : s.Pairing.EffectiveConnection.PinOrNull,
                // FR-134: the Terms acknowledgment round-trips
                // verbatim — an export must never drop or invent an
                // agent's signature on the rulebook.
                s.Pairing.TermsAckVersion,
                s.Pairing.TermsAckHash,
                s.Pairing.TermsAckUtc,
            });
            return JsonSerializer.Serialize(dto);
        }
    }
}
