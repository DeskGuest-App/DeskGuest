using DeskGuest.Shared.Connection;

namespace DeskGuest.Tests;

public class LaneSupervisorTests
{
    [Fact]
    public void NoAddress_IsRetriedForever_NeverBinds()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe(); // always null
        var sup = new LaneSupervisor(probe, clock);
        for (var i = 0; i < 500; i++)
        {
            var actions = sup.Tick(LaneKind.Tailscale);
            Assert.Empty(actions);
            clock.Advance(TimeSpan.FromSeconds(61));
        }
        Assert.Equal(LanePhase.NoAddress, sup.Status(LaneKind.Tailscale).Phase);
    }

    [Fact]
    public void AddressAppears_BindThenBound()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock);
        var actions = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(actions, a => a.Action == "bind" && a.Address == "100.119.105.54");
        sup.ReportBindResult(LaneKind.Tailscale, true);
        Assert.Equal(LanePhase.Bound, sup.Status(LaneKind.Tailscale).Phase);
    }

    [Fact]
    public void AddressChanges_Rebind_AndVanishes_Unbind()
    {
        var clock = new FakeClock();
        var current = "100.119.105.54";
        var probe = new FakeProbe { Handler = _ => current };
        var sup = new LaneSupervisor(probe, clock);
        sup.Tick(LaneKind.Tailscale);
        sup.ReportBindResult(LaneKind.Tailscale, true);

        current = "100.119.105.99";
        var rebind = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(rebind, a => a.Action == "rebind" && a.Address == "100.119.105.99");
        // CLEANUP (Wave 2 Lane B, 2026-11-22): the F11 two-step bind
        // means a rebind tick only BEGINS the bind — the lane is not
        // Bound again until the host reports the bind result (the
        // sibling test AddressAppears_BindThenBound already encodes
        // this). Without this line the vanish tick below ran against
        // a still-binding lane, which correctly emits no "unbind".
        sup.ReportBindResult(LaneKind.Tailscale, true);

        current = null;
        var unbind = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(unbind, a => a.Action == "unbind");
        Assert.Equal(LanePhase.NoAddress, sup.Status(LaneKind.Tailscale).Phase);
    }

    [Fact]
    public void BindFailure_BacksOffBeforeRetrying()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock);
        Assert.NotEmpty(sup.Tick(LaneKind.Tailscale));
        sup.ReportBindResult(LaneKind.Tailscale, false);
        Assert.Equal(LanePhase.BindFailed, sup.Status(LaneKind.Tailscale).Phase);
        Assert.Empty(sup.Tick(LaneKind.Tailscale)); // inside backoff
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.NotEmpty(sup.Tick(LaneKind.Tailscale)); // retry after backoff
    }
}
