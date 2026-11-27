using DeskGuest.Shared.EndpointSecurity;

namespace DeskGuest.Tests;

// RMM-17 test doubles (D38-F12 completion): the recording fakes for
// the RMM-17 seams live HERE, in the test assembly — never in the
// production Shared assembly, so a DI mis-wiring can never
// substitute a fake for real actuation and read "isolated" with no
// actual cut. (Attempt-1's fix removed them from Shared but never
// recreated them here; the Rmm17 test classes did not compile.)

/// <summary>Queue-backed file-activity fake: tests enqueue bursts,
/// the service drains them.</summary>
public sealed class FakeFileActivitySource : IFileActivitySource
{
    private readonly Queue<FileActivityEvent> _queue = new();

    public void Enqueue(IEnumerable<FileActivityEvent> events)
    {
        foreach (var e in events) _queue.Enqueue(e);
    }

    public IReadOnlyList<FileActivityEvent> Drain()
    {
        var drained = _queue.ToList();
        _queue.Clear();
        return drained;
    }
}

/// <summary>Recording network-control fake. ThrowOnApply simulates
/// an actuation failure (the isolation_failed path).</summary>
public sealed class FakeNetworkControl : IEndpointNetworkControl
{
    public bool ThrowOnApply { get; set; }
    public int ApplyCount { get; private set; }
    public int RemoveCount { get; private set; }
    public bool IsIsolationApplied { get; private set; }
    public IsolationPlan? AppliedPlan { get; private set; }

    public void ApplyIsolation(IsolationPlan plan)
    {
        if (ThrowOnApply)
            throw new InvalidOperationException("simulated actuation failure (test fake)");
        ApplyCount++;
        IsIsolationApplied = true;
        AppliedPlan = plan;
    }

    public void RemoveIsolation()
    {
        RemoveCount++;
        IsIsolationApplied = false;
        AppliedPlan = null;
    }
}

/// <summary>Set-backed AV status fake.</summary>
public sealed class FakeAvStatusSource : IAvStatusSource
{
    private IReadOnlyList<AvStatusReading> _readings = Array.Empty<AvStatusReading>();

    public void Set(params AvStatusReading[] readings) => _readings = readings;

    public IReadOnlyList<AvStatusReading> Read(DateTimeOffset now) => _readings;
}
