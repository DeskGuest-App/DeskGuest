namespace Acp.Shared.Connection;

/// <summary>The two first-class lanes (DESIGN §1A.3, §4.2).</summary>
public enum LaneKind { Tailscale, Lan }

public enum LanePhase
{
    NoAddress,   // The lane's address does not exist right now. A STATE, retried forever.
    Bound,       // Listener is bound and serving on this lane.
    BindFailed,  // Address exists but bind failed; backing off, still retrying.
    /// <summary>BD-SHARED-SESSION F11: a bind/rebind action has been
    /// emitted and NO outcome has been reported yet. While Binding,
    /// Tick emits nothing for the lane — the pre-fix code re-emitted
    /// "bind" on every tick until ReportBindResult arrived.</summary>
    Binding
}

/// <summary>Probes the OS for a lane's current address. Windows impl reads
/// interface addresses (tailnet = 100.64.0.0/10); tests use fakes.</summary>
public interface ILaneAddressProbe
{
    string? ProbeAddress(LaneKind lane);
}

/// <summary>Deterministic clock so the supervisor's timing is testable.</summary>
public interface IClock { DateTimeOffset UtcNow { get; } }
public sealed class SystemClock : IClock { public DateTimeOffset UtcNow => DateTimeOffset.UtcNow; }

public sealed record LaneStatus(
    LaneKind Lane,
    LanePhase Phase,
    string? Address,
    DateTimeOffset SinceUtc,
    int ConsecutiveFailures,
    DateTimeOffset NextRetryUtc);

/// <summary>
/// The connection supervisor's decision core (DESIGN §4.2): a state
/// machine, not a startup action. A missing Tailscale address is a
/// reported state retried forever with capped, jittered backoff —
/// NEVER a process exit. This class decides; the host acts (bind/unbind)
/// on the transitions it returns. Pure and deterministic under a fake
/// clock + fake probe, which is how the Linux suite proves the logic
/// that tonight's incumbent failure violated.
/// </summary>
public sealed class LaneSupervisor
{
    private sealed class LaneBook
    {
        public LanePhase Phase = LanePhase.NoAddress;
        public string? Address;
        public DateTimeOffset Since = DateTimeOffset.MinValue;
        public int Failures;
        public DateTimeOffset NextRetry = DateTimeOffset.MinValue;
    }

    // BD-SHARED-SESSION F11: the supervisor is now LOCKED — Tick,
    // ReportBindResult and Status may be called from different host
    // threads (timer + bind callbacks); the pre-fix class had no
    // gate around its lane books.
    private readonly object _gate = new();
    private readonly ILaneAddressProbe _probe;
    private readonly IClock _clock;
    private readonly Func<double>? _jitter; // 0..1 source; null in tests (deterministic)
    private readonly Dictionary<LaneKind, LaneBook> _lanes = new()
    {
        [LaneKind.Tailscale] = new LaneBook(),
        [LaneKind.Lan] = new LaneBook()
    };

    public LaneSupervisor(ILaneAddressProbe probe, IClock clock, Func<double>? jitter = null)
    {
        _probe = probe;
        _clock = clock;
        _jitter = jitter;
    }

    public static readonly TimeSpan BaseRetry = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan MaxRetry = TimeSpan.FromSeconds(60);

    /// <summary>Events the host must act on after a tick.</summary>
    public sealed record Transition(LaneKind Lane, string Action, string? Address); // Action: bind | unbind | rebind

    /// <summary>Advance one lane. Returns host actions. Never throws on a
    /// missing address; a throwing probe is treated as "no address".</summary>
    public IReadOnlyList<Transition> Tick(LaneKind lane)
    {
        lock (_gate)
        {
        var now = _clock.UtcNow;
        var book = _lanes[lane];
        var actions = new List<Transition>();

        // F11: a bind outcome is outstanding — emit nothing until
        // the host reports it. ConnectionDoctor's LaneBound positive
        // evidence is only ever set by ReportBindResult(true).
        if (book.Phase == LanePhase.Binding) return actions;

        if (book.Phase == LanePhase.Bound)
        {
            var current = SafeProbe(lane);
            if (current is null)
            {
                actions.Add(new Transition(lane, "unbind", book.Address));
                SetPhase(book, LanePhase.NoAddress, null, now);
                book.NextRetry = now; // re-probe promptly; backoff applies to failures, not to waiting
            }
            else if (!string.Equals(current, book.Address, StringComparison.Ordinal))
            {
                // F11: a rebind is an unbind + a bind WITH an outcome
                // report — the lane leaves Bound and enters Binding,
                // so it is never reported bound on an address whose
                // bind may have failed.
                actions.Add(new Transition(lane, "unbind", book.Address));
                actions.Add(new Transition(lane, "rebind", current));
                book.Phase = LanePhase.Binding;
                book.Address = current;
                book.Since = now;
            }
            return actions;
        }

        // Not bound: respect backoff.
        if (now < book.NextRetry) return actions;

        var address = SafeProbe(lane);
        if (address is null)
        {
            // Still no address: stay in the state, schedule the next look.
            // This is the loop the incumbent never had. The wait GROWS
            // (failures increment) to the cap — no 2-second spin (L1).
            book.Phase = LanePhase.NoAddress;
            book.Failures++;
            book.NextRetry = now + Backoff(book.Failures);
            return actions;
        }

        actions.Add(new Transition(lane, "bind", address));
        book.Address = address;
        book.Phase = LanePhase.Binding; // F11: suppress re-emits until the outcome lands
        return actions;
        }
    }

    /// <summary>Host reports the outcome of a bind action.</summary>
    public void ReportBindResult(LaneKind lane, bool success)
    {
        lock (_gate)
        {
        var now = _clock.UtcNow;
        var book = _lanes[lane];
        if (success)
        {
            book.Phase = LanePhase.Bound;
            book.Since = now;
            book.Failures = 0;
            book.NextRetry = DateTimeOffset.MinValue;
        }
        else
        {
            book.Phase = LanePhase.BindFailed;
            book.Failures++;
            book.NextRetry = now + Backoff(book.Failures);
        }
        }
    }

    public LaneStatus Status(LaneKind lane)
    {
        lock (_gate)
        {
            var b = _lanes[lane];
            return new LaneStatus(lane, b.Phase, b.Address, b.Since, b.Failures, b.NextRetry);
        }
    }

    /// <summary>True while the tailnet lane has no bound address — the
    /// endpoint's §4.1 TAILSCALE_DOWN characterization input.</summary>
    public bool TailscaleUnavailable { get { lock (_gate) return _lanes[LaneKind.Tailscale].Phase != LanePhase.Bound; } }

    private string? SafeProbe(LaneKind lane)
    {
        try { return _probe.ProbeAddress(lane); }
        catch { return null; } // a broken probe is "no address", never a crash
    }

    private static void SetPhase(LaneBook book, LanePhase phase, string? address, DateTimeOffset now)
    {
        book.Phase = phase;
        book.Address = address;
        book.Since = now;
    }

    private TimeSpan Backoff(int failures)
    {
        // F11: jitter is applied BEFORE the cap — the pre-fix order
        // (cap, then ×1.25) produced waits of ~75 s against a
        // documented 60 s cap.
        var seconds = BaseRetry.TotalSeconds * Math.Pow(2, Math.Min(failures, 5));
        if (_jitter is not null) seconds *= 1 + 0.25 * Math.Clamp(_jitter(), 0, 1);
        return TimeSpan.FromSeconds(Math.Min(MaxRetry.TotalSeconds, seconds));
    }
}
