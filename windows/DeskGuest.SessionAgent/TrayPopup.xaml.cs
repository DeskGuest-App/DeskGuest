using System.Windows;

namespace DeskGuest.SessionAgent;

/// <summary>The tray popup (M4, design image 33): the host's state at
/// a glance — server line, live session line with a STOP that works,
/// this PC's mesh line — and the way into the dashboard. Every line
/// is a fact read at show time from the agent's live channels;
/// nothing is cached or invented. The mesh line comes from the
/// host-state snapshot the Core pushes over IPC (Block H: the
/// popup's old loopback HTTP fetch targeted a lane production
/// never starts, so it could only ever fail — the line now shares
/// the host window's one source and updates live while the popup
/// is open). Closes when it loses activation, like a tray popup
/// should.</summary>
public partial class TrayPopup : Window
{
    private readonly Func<Task> _onStop;
    private readonly Action _onOpenDashboard;

    public TrayPopup(string headerLine, string sessionLine, string sessionSub, bool stopInForce,
        string meshLine, Func<Task> onStop, Action onOpenDashboard)
    {
        InitializeComponent();
        HeaderLine.Text = headerLine;
        SessionLine.Text = sessionLine;
        SessionSub.Text = sessionSub;
        MeshLine.Text = meshLine;
        StopButton.Content = stopInForce ? Strings.Get("StopIsInForce") : Strings.Get("StopSession");
        StopButton.IsEnabled = !stopInForce;
        _onStop = onStop;
        _onOpenDashboard = onOpenDashboard;
        Deactivated += (_, _) => Close();
    }

    /// <summary>Live-update the mesh line when a fresher snapshot
    /// lands while the popup is open (the App pushes it).</summary>
    public void SetMeshLine(string meshLine)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetMeshLine(meshLine)); return; }
        MeshLine.Text = meshLine;
    }

    /// <summary>Position at the bottom-right of the primary screen's
    /// work area, above the taskbar.</summary>
    public void PlaceAtTray()
    {
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width - 6;
        Top = area.Bottom - ActualHeight - 6;
        if (ActualHeight <= 0)
            SizeChanged += (_, _) => Top = area.Bottom - ActualHeight - 6;
    }

    private async void Stop_Click(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        await _onStop();
        Close();
    }

    private void Dashboard_Click(object sender, RoutedEventArgs e)
    {
        _onOpenDashboard();
        Close();
    }
}
