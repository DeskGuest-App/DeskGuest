using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;

namespace Acp.Shared.Threading;

/// <summary>
/// FR-138 — a dedicated single-thread-apartment (STA) thread for
/// work that Windows only allows from an STA thread (the OLE
/// clipboard above all), callable from any thread.
///
/// The desktop engine executes tools on the IPC channel's
/// thread-pool threads, which are MTA. Its clipboard methods
/// called the WPF clipboard directly from there, so the FIRST
/// clipboard write that ever survived the approval gate died at
/// execution with ThreadStateException ("Current thread must be
/// set to single thread apartment (STA) mode before OLE calls
/// can be made") — the owner had approved the action and it
/// still never happened (Tested-AI battery run 5, 2026-11-25).
/// Every earlier attempt had been denied, gated, or timed out
/// upstream of execution, which is why the path looked healthy.
///
/// The fix is a class fix, not a call-site patch: ONE dedicated
/// STA thread with a work queue lives for the process; any
/// OLE-bound work routes through <see cref="Invoke{T}"/> and
/// runs there, with its result (or its exception, stack intact)
/// carried back to the caller. The queue is deliberately boring:
/// work items run one at a time, in arrival order, and a throwing
/// item never kills the thread.
///
/// Apartment state exists only on Windows; on other hosts the
/// queue still runs (the clipboard itself is Windows-only, so
/// non-Windows hosts never route real work here).
/// </summary>
public static class StaDispatcher
{
    private static readonly BlockingCollection<WorkItem> Queue = new();
    private static readonly object StartLock = new();
    private static Thread? _thread;

    /// <summary>Run <paramref name="work"/> on the dedicated STA
    /// thread and return its result. An exception the work throws
    /// is rethrown on the calling thread with its stack intact —
    /// a failure is reported, never swallowed.</summary>
    public static T Invoke<T>(Func<T> work)
    {
        ArgumentNullException.ThrowIfNull(work);
        EnsureThread();
        var item = new WorkItem<T>(work);
        Queue.Add(item);
        return item.AwaitResult();
    }

    /// <summary>Run <paramref name="work"/> on the dedicated STA
    /// thread, for work with no result to carry back.</summary>
    public static void Invoke(Action work)
    {
        ArgumentNullException.ThrowIfNull(work);
        Invoke<object?>(() => { work(); return null; });
    }

    /// <summary>The dedicated thread's managed id once it exists
    /// (diagnostics and tests).</summary>
    public static int? DispatcherThreadId => _thread?.ManagedThreadId;

    private static void EnsureThread()
    {
        if (_thread is not null) return;
        lock (StartLock)
        {
            if (_thread is not null) return;
            var t = new Thread(Run) { IsBackground = true, Name = "AcpStaDispatcher" };
            if (OperatingSystem.IsWindows())
                t.SetApartmentState(ApartmentState.STA);
            t.Start();
            _thread = t;
        }
    }

    private static void Run()
    {
        foreach (var item in Queue.GetConsumingEnumerable())
            item.Execute();
    }

    private abstract class WorkItem
    {
        public abstract void Execute();
    }

    private sealed class WorkItem<T> : WorkItem
    {
        private readonly Func<T> _work;
        private readonly ManualResetEventSlim _done = new(false);
        private T? _result;
        private ExceptionDispatchInfo? _error;

        public WorkItem(Func<T> work) => _work = work;

        public override void Execute()
        {
            try { _result = _work(); }
            catch (Exception ex) { _error = ExceptionDispatchInfo.Capture(ex); }
            _done.Set();
        }

        public T AwaitResult()
        {
            _done.Wait();
            _error?.Throw();
            return _result!;
        }
    }
}
