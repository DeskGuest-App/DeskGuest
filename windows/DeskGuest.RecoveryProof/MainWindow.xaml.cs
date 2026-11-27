using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace DeskGuest.RecoveryProof;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        if (App.DarkTheme) ApplyDarkTheme();
    }

    // Dark theme values from deskguest-tokens.css [data-theme="dark"].
    private void ApplyDarkTheme()
    {
        (string Key, string Hex)[] map =
        {
            ("BgBrush", "#0F2537"), ("SurfaceBrush", "#163147"), ("Surface2Brush", "#1E3E58"),
            ("TextBrush", "#F2F6F9"), ("MutedBrush", "#A8C0D4"), ("BorderBrush", "#234663"),
            ("TitlebarBrush", "#163147"), ("RailBrush", "#0B1C2A"), ("RailSearchBrush", "#163147"),
            ("IconBrush", "#F2F6F9"), ("IconTileBrush", "#1E3E58"),
            ("BadgeTealBg", "#1D4048"), ("BadgeTealText", "#8FC1C1"),
            ("BadgeMutedBg", "#1E3E58"), ("BadgeMutedText", "#A8C0D4"),
            ("GoldTileBrush", "#3A2E14"),
        };
        foreach (var (key, hex) in map)
        {
            if (Resources[key] is SolidColorBrush brush)
                brush.Color = (Color)ColorConverter.ConvertFromString(hex);
        }
    }

    private void OnTitlebarDrag(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximise(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
