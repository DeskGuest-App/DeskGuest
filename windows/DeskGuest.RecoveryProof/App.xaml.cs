using System.Windows;

namespace DeskGuest.RecoveryProof;

public partial class App : Application
{
    public static bool DarkTheme { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        DarkTheme = e.Args.Any(a => a.Equals("dark", StringComparison.OrdinalIgnoreCase));
        base.OnStartup(e);
    }
}
