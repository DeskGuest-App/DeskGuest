namespace DeskGuest.Shared.Compliance;

// =====================================================================
// RMM-09 — hub-side fact-source stores for the facts that have no
// other hub home yet. RMM-01 evaluates security state ON the
// endpoint (AV / firewall / encryption); the hub-side persistence
// of those samples is this store — the integration seam where the
// monitor's reports land. It keeps only the LATEST state per
// device, with the instant it was OBSERVED on the endpoint: the
// compiler's freshness judgment runs from that instant, so an old
// sample can never be re-presented as current by re-reporting it.
// =====================================================================

/// <summary>One device's latest observed security state (mirrors
/// RMM-01's SecurityStateSample shape without coupling the
/// compliance layer to the monitoring layer's types). A null field
/// means "not read" — the fact builder emits NO fact for a control
/// whose underlying value was not read (missing_fact), never a
/// guessed one.</summary>
public sealed record DeviceSecurityState(
    string DeviceId,
    string ScopeId,
    bool? AvEnabled,
    bool? FirewallEnabled,
    bool? EncryptionEnabled,
    DateTimeOffset ObservedUtc);

public sealed class SecurityStateStore
{
    private readonly Dictionary<string, DeviceSecurityState> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _now;

    /// <param name="now">The hub's clock (the service passes its
    /// own; defaults to the wall clock). D38-F3: an observation
    /// dated further in the future than
    /// <see cref="ComplianceLimits.MaxFutureSkew"/> refuses —
    /// before this fix a report stamped now+1y was accepted and
    /// then poisoned the store for a year, every real report
    /// refusing as a "stale replay" against the future one.</param>
    public SecurityStateStore(Func<DateTimeOffset>? now = null) =>
        _now = now ?? (() => DateTimeOffset.UtcNow);

    /// <summary>Record a security-state observation. An observation
    /// OLDER than the stored one refuses (returns false): replaying
    /// last week's "encryption on" over today's "encryption off"
    /// is stale-fact laundering and the store will not hold it. A
    /// FUTURE-dated observation (beyond clock skew) refuses too:
    /// it would win every freshness judgment for its whole
    /// lifetime and block every real report behind it.</summary>
    public bool Record(DeviceSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ObservedUtc > _now() + ComplianceLimits.MaxFutureSkew)
            return false;
        lock (_gate)
        {
            if (_byDevice.TryGetValue(state.DeviceId, out var existing) &&
                state.ObservedUtc <= existing.ObservedUtc)
                return false;
            _byDevice[state.DeviceId] = state;
            return true;
        }
    }

    public DeviceSecurityState? Get(string deviceId)
    {
        lock (_gate) return deviceId is not null && _byDevice.TryGetValue(deviceId, out var s) ? s : null;
    }

    public IReadOnlyList<DeviceSecurityState> List(string? scopeId = null)
    {
        lock (_gate) return _byDevice.Values
            .Where(s => scopeId is null || string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(s => s.DeviceId, StringComparer.Ordinal).ToList();
    }
}
