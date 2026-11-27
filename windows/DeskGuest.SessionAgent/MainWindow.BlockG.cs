using System.Windows;
using System.Windows.Controls;
using DeskGuest.Shared.Ipc;
using Button = System.Windows.Controls.Button;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The Services page (Block H — the device-side exposure of the
/// Block G services): Wake-on-LAN registry + send, standalone
/// transfers, session tunnels, and local second-factor posture.
/// Every control is a thin carrier over the authenticated
/// laptop-UI channel — the Core's services are the authority and
/// their refusals surface verbatim. This page is also the F7
/// device-side transfer presence: a person at this machine can
/// always see live transfer jobs and stop one, whoever started
/// it — a device-presence stop in the service itself (D38 fix
/// F10), recorded in the chained audit under the reserved
/// device-console actor, never under a roster id typed into a
/// box. Roster acts (wake registry, wake send) still name the
/// acting roster user, and the services verify that user against
/// the live roster before anything is attributed to them.
/// Existing page patterns only; no new design language.
/// </summary>
public partial class MainWindow
{
    private StackPanel? _blockGFacts;
    private TextBlock? _blockGStatus;

    private UIElement BuildServicesPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Services"));
        stack.Children.Add(Sub("Wake-on-LAN, standalone file transfers, session tunnels, and second factors — the Block G services, reachable from this machine. The services enforce every rule themselves; this page only carries the acts and shows their answers."));
        _blockGStatus = Muted("");
        _blockGFacts = new StackPanel();
        stack.Children.Add(_blockGFacts);
        stack.Children.Add(_blockGStatus);

        TextBox Box(string tip, double width = 210) => new()
        {
            Width = width, Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center, ToolTip = tip,
        };
        Button Ghost(string label) => new()
        {
            Content = label, Style = (Style)FindResource("GhostButton"),
            Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5),
        };
        StackPanel Row() => new() { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        void Section(StackPanel body, string title)
        {
            body.Children.Add(new TextBlock { Text = title, FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 4) });
        }

        // ---- wake-on-LAN ----
        var wake = new StackPanel();
        Section(wake, "Wake-on-LAN");
        wake.Children.Add(MutedT("The target registry is written only by a company admin (or this host itself). Sending a wake needs the 'use' grant on the device's group and the wake_on_lan policy toggle for the scope.", "The acting user is the roster user you are acting as — the service checks that user against the live roster (admin for registry writes, grant for sends) before the act is attributed to them."));
        var wakeActor = Box("Your roster user id (admin for registry writes; grant holder for sends)");
        var wakeDevice = Box("Device id");
        var wakeMac = Box("MAC address, e.g. 00:11:22:33:44:55");
        var wakeBroadcast = Box("Broadcast address (blank = 255.255.255.255)", 170);
        var wakeRow1 = Row();
        wakeRow1.Children.Add(new TextBlock { Text = "Acting user", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        wakeRow1.Children.Add(wakeActor);
        wakeRow1.Children.Add(new TextBlock { Text = "Device", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        wakeRow1.Children.Add(wakeDevice);
        wake.Children.Add(wakeRow1);
        var wakeRow2 = Row();
        wakeRow2.Children.Add(new TextBlock { Text = "MAC", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        wakeRow2.Children.Add(wakeMac);
        wakeRow2.Children.Add(new TextBlock { Text = "Broadcast", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        wakeRow2.Children.Add(wakeBroadcast);
        wake.Children.Add(wakeRow2);
        var wakeRow3 = Row();
        var wakeList = Ghost("List targets");
        wakeList.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "wake_list" }, _blockGStatus);
        var wakeRegister = Ghost("Register target");
        wakeRegister.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "wake_register", actorUserId = wakeActor.Text.Trim(), deviceId = wakeDevice.Text.Trim(), mac = wakeMac.Text.Trim(), broadcast = wakeBroadcast.Text.Trim() }, _blockGStatus);
        var wakeUnregister = Ghost("Remove target");
        wakeUnregister.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "wake_unregister", actorUserId = wakeActor.Text.Trim(), deviceId = wakeDevice.Text.Trim() }, _blockGStatus);
        var wakeSend = Ghost("Wake device");
        wakeSend.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "wake_send", actorUserId = wakeActor.Text.Trim(), deviceId = wakeDevice.Text.Trim() }, _blockGStatus);
        wakeRow3.Children.Add(wakeList);
        wakeRow3.Children.Add(wakeRegister);
        wakeRow3.Children.Add(wakeUnregister);
        wakeRow3.Children.Add(wakeSend);
        wake.Children.Add(wakeRow3);
        stack.Children.Add(Card(wake));

        // ---- standalone transfers (device-side presence + stop) ----
        var transfers = new StackPanel();
        Section(transfers, "Standalone transfers");
        transfers.Children.Add(Muted("Session-less transfer jobs in a scope. Anyone at this machine can see them and stop one, whoever started it — stopping is a device-presence act, recorded in the audit as this console's stop, not under any typed name."));
        var transferScope = Box("Scope id");
        var transferJob = Box("Transfer job id");
        var transferRow1 = Row();
        transferRow1.Children.Add(new TextBlock { Text = "Scope", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        transferRow1.Children.Add(transferScope);
        var listJobs = Ghost("List jobs in scope");
        listJobs.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "transfers_list", scopeId = transferScope.Text.Trim() }, _blockGStatus);
        transferRow1.Children.Add(listJobs);
        transfers.Children.Add(transferRow1);
        var transferRow2 = Row();
        transferRow2.Children.Add(new TextBlock { Text = "Job", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        transferRow2.Children.Add(transferJob);
        var cancelJob = Ghost("Stop this transfer");
        cancelJob.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "transfer_cancel_device", jobId = transferJob.Text.Trim() }, _blockGStatus);
        transferRow2.Children.Add(cancelJob);
        transfers.Children.Add(transferRow2);
        stack.Children.Add(Card(transfers));

        // ---- session tunnels ----
        var tunnels = new StackPanel();
        Section(tunnels, "Session tunnels");
        tunnels.Children.Add(Muted("Open TCP tunnels riding live sessions. Tunnels open inside human sessions only — an AI actor is refused by the service itself. Closing one from here is the device-side stop: the person at this machine can close any tunnel, recorded as this console's act."));
        var tunnelScope = Box("Scope id");
        var tunnelId = Box("Tunnel id");
        var tunnelRow1 = Row();
        tunnelRow1.Children.Add(new TextBlock { Text = "Scope", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        tunnelRow1.Children.Add(tunnelScope);
        var listTunnels = Ghost("List open tunnels");
        listTunnels.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "tunnels_list", scopeId = tunnelScope.Text.Trim() }, _blockGStatus);
        tunnelRow1.Children.Add(listTunnels);
        tunnels.Children.Add(tunnelRow1);
        var tunnelRow2 = Row();
        tunnelRow2.Children.Add(new TextBlock { Text = "Tunnel", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        tunnelRow2.Children.Add(tunnelId);
        var closeTunnel = Ghost("Close tunnel");
        closeTunnel.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "tunnel_close_device", tunnelId = tunnelId.Text.Trim() }, _blockGStatus);
        tunnelRow2.Children.Add(closeTunnel);
        tunnels.Children.Add(tunnelRow2);
        stack.Children.Add(Card(tunnels));

        // ---- second factors ----
        var factors = new StackPanel();
        Section(factors, "Second factors");
        factors.Children.Add(Muted("Local TOTP and passkey posture on this host. Counts only — which users hold factors, and any factor material, never surface here."));
        var factorRow = Row();
        var factorStatus = Ghost("Factor status");
        factorStatus.Click += async (_, _) => await SendHostActionAsync(IpcKinds.BlockGAction,
            new { action = "factor_status" }, _blockGStatus);
        factorRow.Children.Add(factorStatus);
        factors.Children.Add(factorRow);
        stack.Children.Add(Card(factors));

        RenderBlockG();
        return new ScrollViewer { Content = stack, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    }

    private void RenderBlockG()
    {
        if (_blockGFacts is null) return;
        _blockGFacts.Children.Clear();
        var facts = _host?.BlockG;
        if (facts is null)
        {
            _blockGFacts.Children.Add(Muted("The Core has not reported service facts yet — this page fills in from the live snapshot."));
            return;
        }
        _blockGFacts.Children.Add(Muted(
            $"Wake targets registered: {facts.WakeTargets} · standalone transfer jobs live: {facts.StandaloneJobsLive} · " +
            $"session tunnels open: {facts.SessionTunnelsOpen} · TOTP enrollments active: {facts.TotpEnrollmentsActive} · passkeys registered: {facts.PasskeysRegistered}"));
        foreach (var (key, state) in facts.FeatureStates)
            _blockGFacts.Children.Add(Muted($"Policy · {key}: {state}"));
    }
}
