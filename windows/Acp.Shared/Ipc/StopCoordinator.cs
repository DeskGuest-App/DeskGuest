namespace Acp.Shared.Ipc;

/// <summary>
/// BD-WIN-AGENT F5: the STOP-precedence mechanism. Tool requests used
/// to run inline on the IPC read loop, so StopAll / ReleaseInputs /
/// presence-off queued behind whatever tool was running — a long
/// type_text kept typing after STOP and shell_exec had no deadline
/// at all. The coordinator owns the "current work" cancellation
/// source: the read loop dispatches tool requests onto their own
/// tasks with <see cref="CurrentToken"/>; any STOP trigger (Core
/// StopAll, presence stop/off, local STOP press, link loss) calls
/// <see cref="CancelCurrentWork"/>, which cancels the in-flight work
/// AND installs a fresh source so the next tool starts un-cancelled.
/// Thread-safe; cancelling with nothing running is a no-op that
/// still rotates the source.
/// </summary>
public sealed class StopCoordinator : IDisposable
{
    private readonly object _gate = new();
    private CancellationTokenSource _current = new();
    private bool _disposed;

    /// <summary>The token the currently-dispatched tool work runs
    /// under. Snapshot it at dispatch time; a later STOP cancels
    /// exactly that snapshot.</summary>
    public CancellationToken CurrentToken
    {
        get { lock (_gate) return _current.Token; }
    }

    /// <summary>Cancel whatever tool work is in flight and arm a
    /// fresh token for the next dispatch. Returns true when the
    /// cancelled source had a live registration (best-effort signal
    /// for narration; the guarantee is the cancellation itself).</summary>
    public bool CancelCurrentWork()
    {
        lock (_gate)
        {
            if (_disposed) return false;
            var old = _current;
            _current = new CancellationTokenSource();
            try { old.Cancel(); } catch { /* a faulty callback never blocks STOP */ }
            old.Dispose();
            return true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try { _current.Cancel(); } catch { }
            _current.Dispose();
        }
    }
}
