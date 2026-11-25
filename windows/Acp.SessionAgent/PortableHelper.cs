using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Acp.Shared.Ipc;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace Acp.SessionAgent;

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
        Width = 520;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ResizeMode = ResizeMode.NoResize;

        var stack = new StackPanel { Margin = new Thickness(24) };
        stack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableTitle"), FontSize = 26, FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4),
        });
        stack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableIntro"),
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12),
        });
        _codeText = new TextBlock
        {
            Text = "— — — —  — — — —", FontSize = 34, FontWeight = FontWeights.SemiBold,
            FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 4, 0, 4),
        };
        stack.Children.Add(_codeText);
        stack.Children.Add(new TextBlock
        {
            Text = Strings.Get("PortableCodeHint"),
            FontSize = 12.5, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12),
        });
        var mint = new Button
        {
            Content = Strings.Get("PortableShowCode"), Padding = new Thickness(14, 8, 14, 8),
            HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 12),
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
            Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 15,
            Padding = new Thickness(16, 10, 16, 10), HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 4, 0, 8),
        };
        stop.Click += async (_, _) =>
        {
            var sent = await _sendStop();
            _status.Text = sent ? Strings.Get("PortableStopSent")
                : Strings.Get("PortableStopFailed");
        };
        stack.Children.Add(stop);
        _status = new TextBlock { FontSize = 12.5, TextWrapping = TextWrapping.Wrap };
        stack.Children.Add(_status);
        Content = stack;

        Closing += (_, _) =>
        {
            // The code dies when the helper closes — fire the close
            // on the way out; the process exit is the guarantee, the
            // Core-side close is the record.
            if (_displayCode is not null)
                _ = _sendAction(IpcKinds.QuickAssistAction, new { action = "close", code = _displayCode });
        };
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
