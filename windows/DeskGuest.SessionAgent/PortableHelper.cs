using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeskGuest.Shared.Ipc;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The portable quick-assist helper (Block F, D24b): the
/// SessionAgent in portable, no-install mode. A person being helped
/// runs this single file for ONE session:
///
///   • presence is up from the first second (the layer is driven
///     locally the moment the window opens — nobody waits for a
///     session to learn they are visible);
///   • the window shows the session code (minted by the local Core)
///     for the helped person to read to their helper;
///   • STOP is always on the window, wired to the same user-stop
///     as the installed agent;
///   • closing the window burns the code (the Core closes the code
///     and any grant with it) and the process exits — nothing was
///     installed, nothing is left running, no tray, no persistence.
///
/// It never shows the host window, the roster, or any admin
/// surface: a helped person gets exactly this window.
/// </summary>
public sealed class PortableHelperWindow : Window
{
    private readonly Func<string, object, Task<bool>> _sendAction;
    private readonly Func<Task<bool>> _sendStop;
    private readonly TextBlock _codeText;
    private readonly TextBlock _status;
    private string? _displayCode;
    private string _deviceId = "";
    private string _scopeId = "";

    public PortableHelperWindow(Func<string, object, Task<bool>> sendAction, Func<Task<bool>> sendStop)
    {
        _sendAction = sendAction;
        _sendStop = sendStop;
        Title = Strings.Get("PortableWindowTitle");
        Width = 560;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ResizeMode = ResizeMode.NoResize;
        // #153 (N16): the start face rebuilt in the Quick Fix A1
        // language — light canvas, one white card, navy title, the
        // Terms moment in a tinted panel, the anti-scam line in a
        // red-accent panel, the code centred in its own panel, the
        // mint act as the blue primary, STOP red full width.
        // Presentation only: every word still comes from Strings,
        // every act is wired exactly as before.
        Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xEF, 0xF5));
        var navy = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37));
        var body = new SolidColorBrush(Color.FromRgb(0x2C, 0x3A, 0x47));
        var muted = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75));

        var card = new Border
        {
            Background = Brushes.White, CornerRadius = new CornerRadius(14),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE7, 0xEE, 0xF4)),
            BorderThickness = new Thickness(1), Margin = new Thickness(16),
            Padding = new Thickness(28, 24, 28, 24),
        };
        var stack = new StackPanel();
        card.Child = stack;
        Content = card;
        stack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableTitle"), FontSize = 30, FontWeight = FontWeights.ExtraBold,
            Foreground = navy, Margin = new Thickness(0, 0, 0, 6),
        });
        stack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableIntro"), Foreground = body,
            FontSize = 14.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 14),
        });
        // Terms moment (Terms §2): Quick Fix has no install, so its
        // start screen carries the short-form claims, the full Terms
        // one tap away, and the mint act below records acceptance.
        var termsPanel = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xED, 0xF2, 0xF7)),
            CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 12, 14, 10),
            Margin = new Thickness(0, 0, 0, 12),
        };
        var termsStack = new StackPanel();
        termsPanel.Child = termsStack;
        termsStack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableTerms"), Foreground = body,
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
        });
        var termsLink = new Button
        {
            Content = Strings.Get("PortableTermsLink"),
            FontSize = 13.5, FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x35, 0x60, 0x6A)),
            Background = Brushes.Transparent, BorderThickness = new Thickness(0),
            Padding = new Thickness(0, 2, 0, 2),
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        termsLink.Click += (_, _) =>
        {
            // The single public rendering of the canonical Terms
            // (BUILD-PROGRAMME, Terms linkage) — one tap away.
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://deskguest.app/terms.html",
                    UseShellExecute = true,
                });
            }
            catch { _status.Text = "https://deskguest.app/terms.html"; }
        };
        termsStack.Children.Add(termsLink);
        stack.Children.Add(termsPanel);
        var scamPanel = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xFD, 0xEC, 0xEC)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
            BorderThickness = new Thickness(4, 0, 0, 0),
            CornerRadius = new CornerRadius(6), Padding = new Thickness(12, 10, 12, 10),
            Margin = new Thickness(0, 0, 0, 14),
        };
        scamPanel.Child = new TextBlock
        {
            Text = Strings.Get("PortableAntiScam"),
            FontSize = 13.5, FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x9C, 0x2B, 0x2B)),
            TextWrapping = TextWrapping.Wrap,
        };
        stack.Children.Add(scamPanel);
        var codePanel = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xED, 0xF2, 0xF7)),
            CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 12, 14, 12),
            Margin = new Thickness(0, 0, 0, 8),
        };
        var codeStack = new StackPanel();
        codePanel.Child = codeStack;
        _codeText = new TextBlock
        {
            Text = "— — — —  — — — —", FontSize = 38, FontWeight = FontWeights.SemiBold,
            FontFamily = new FontFamily("Consolas"), Foreground = navy,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 2, 0, 2),
        };
        codeStack.Children.Add(_codeText);
        codeStack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableCodeHint"), Foreground = muted,
            FontSize = 13, TextWrapping = TextWrapping.Wrap,
            HorizontalAlignment = HorizontalAlignment.Center,
        });
        stack.Children.Add(codePanel);
        var mint = new Button
        {
            Content = Strings.Get("PortableShowCode"),
            Background = new SolidColorBrush(Color.FromRgb(0x26, 0x84, 0xC2)),
            Foreground = Brushes.White, FontSize = 16, FontWeight = FontWeights.SemiBold,
            BorderThickness = new Thickness(0), Padding = new Thickness(14, 11, 14, 11),
            Template = FlatTemplate(),
            HorizontalAlignment = HorizontalAlignment.Stretch, Margin = new Thickness(0, 4, 0, 10),
        };
        mint.Click += async (_, _) =>
        {
            var sent = await _sendAction(IpcKinds.QuickAssistAction, new
            {
                action = "mint", scopeId = _scopeId, hostDeviceId = _deviceId, initiatorUserId = "portable-helper",
            });
            _status.Text = sent ? Strings.Get("PortableAskingCode") : Strings.Get("PortableCodeNotMinted");
        };
        stack.Children.Add(mint);
        var stop = new Button
        {
            Content = Strings.Get("PortableStop"),
            Background = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
            Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 16,
            BorderThickness = new Thickness(0), Template = FlatTemplate(),
            Padding = new Thickness(16, 12, 16, 12), HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 0, 0, 10),
        };
        stop.Click += async (_, _) =>
        {
            var sent = await _sendStop();
            _status.Text = sent ? Strings.Get("PortableStopSent")
                : Strings.Get("PortableStopFailed");
        };
        stack.Children.Add(stop);
        _status = new TextBlock
        {
            FontSize = 13, Foreground = muted, TextWrapping = TextWrapping.Wrap,
            HorizontalAlignment = HorizontalAlignment.Center,
        };
        stack.Children.Add(_status);

        Closing += (_, _) =>
        {
            // The code dies when the helper closes — fire the close
            // on the way out; the process exit is the guarantee, the
            // Core-side close is the record.
            if (_displayCode is not null)
                _ = _sendAction(IpcKinds.QuickAssistAction, new { action = "close", code = _displayCode });
        };
    }


    /// <summary>#153: a flat button template — the Windows 11 default
    /// template washes a coloured button pale on hover (live-caught on
    /// the STOP and on A1's Host button); the flat template keeps the
    /// button's own colour in every state, so STOP stays red.</summary>
    private static System.Windows.Controls.ControlTemplate FlatTemplate()
    {
        var border = new System.Windows.FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.BackgroundProperty, new System.Windows.TemplateBindingExtension(Button.BackgroundProperty));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        var presenter = new System.Windows.FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.AppendChild(presenter);
        return new System.Windows.Controls.ControlTemplate(typeof(Button)) { VisualTree = border };
    }

    /// <summary>The Core's minted code (QuickAssistCode IPC),
    /// shown once, here, to the person being helped.</summary>
    public void SetCode(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetCode(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            _displayCode = doc.RootElement.GetProperty("code").GetString() ?? "";
            _codeText.Text = string.Join(" ", _displayCode.ToCharArray());
            _status.Text = Strings.Get("PortableCodeMinted");
        }
        catch { }
    }

    /// <summary>Learn this endpoint's device id + scope from the
    /// Core snapshot, so the minted code binds to the real device.</summary>
    public void SetHostState(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("endpoint", out var ep) &&
                ep.TryGetProperty("device", out var dev))
            {
                if (dev.TryGetProperty("deviceId", out var id)) _deviceId = id.GetString() ?? "";
                if (dev.TryGetProperty("scope", out var sc)) _scopeId = sc.GetString() ?? "";
            }
        }
        catch { }
    }
}
