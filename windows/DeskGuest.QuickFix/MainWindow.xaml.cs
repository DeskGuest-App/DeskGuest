using System.Diagnostics;
using System.Windows;

namespace DeskGuest.QuickFix;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximise(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    // Step 1 is the whole built surface in this tranche: the Host/Join
    // taps are real, and they say plainly that the Step 2 choice
    // (Session or Room, spec M-35) is not built yet — no dead end,
    // no pretend session. Nothing is started by these taps, so no
    // Terms acceptance is recorded here; acceptance records when a
    // session actually starts (Terms §2).
    private void OnHost(object sender, RoutedEventArgs e) =>
        StatusLine.Text = "Host: the next step — Session or Room — isn't built yet. Nothing has been started.";

    private void OnJoin(object sender, RoutedEventArgs e) =>
        StatusLine.Text = "Join: the next step — Session or Room — isn't built yet. Nothing has been started.";

    private void OnHelp(object sender, RoutedEventArgs e) =>
        StatusLine.Text = "Host starts a help session or a room. Join enters one with a one-time code or an invite link. Full help isn't built yet.";

    private void OnTerms(object sender, RoutedEventArgs e)
    {
        // The full Terms, one tap away: the single public rendering
        // of the canonical Terms text (BUILD-PROGRAMME, Terms linkage).
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://deskguest.app/terms.html",
                UseShellExecute = true,
            });
        }
        catch
        {
            StatusLine.Text = "The full Terms are at deskguest.app/terms.html";
        }
    }
}
