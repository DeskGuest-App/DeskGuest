using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DeskGuest.Shared.Streaming;
// The agent compiles with both WPF and WinForms in scope; the
// viewer is WPF-only, so pin the names that collide — the same
// alias block the other MainWindow partials carry (Block D
// recovery 2026-11-19: without these aliases this file never
// compiled — the test gate does not build the agent project).
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using Image = System.Windows.Controls.Image;
using MouseEventArgs = System.Windows.Input.MouseEventArgs;
using Orientation = System.Windows.Controls.Orientation;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The operator-side session-stream viewer (Block D) in the host
/// window's Sessions surface. It consumes the SAME mesh stream the
/// phone consumes — over the loopback lane (http://127.0.0.1:8741,
/// the Core's shipped port) — so what the operator sees is what a
/// remote viewer sees: DGSF envelopes validated by StreamProtocol,
/// decoded by the in-box Media Foundation H.264 decoder, rendered
/// with the roster and floor state from /mesh/stream/info, and the
/// floor holder's name riding the frame's cursor position (D35's
/// named cursor; when the AI holds the floor its name rides its
/// ghost pointer).
///
/// Input from this viewer is ordinary stream input: it is sent as
/// the actor id typed in the session surface and the Core's stream
/// layer accepts it ONLY while that actor holds the floor — the
/// refusal text is shown verbatim when it does not. The host's
/// out-of-band powers (STOP, take floor back) live in the session
/// surface above, not here.
/// </summary>
public partial class MainWindow
{
    private static readonly HttpClient StreamHttp = new() { Timeout = TimeSpan.FromSeconds(6) };
    private const string StreamBase = "http://127.0.0.1:8741";

    private StackPanel? _streamPanel;
    private Image? _streamImage;
    private TextBlock? _streamStatus;
    private TextBlock? _streamFloorLine;
    private StackPanel? _streamRosterBody;
    private Border? _streamCursorChip;
    private TextBlock? _streamCursorChipText;
    private Canvas? _streamCanvas;
    private CancellationTokenSource? _streamCts;
    private H264Decoder? _streamDecoder;
    private string? _streamSessionId;
    private long _streamSeq;
    private int _streamFrameWidth, _streamFrameHeight;
    private string? _streamFloorName;

    private void RenderStreamSection(HumanSessionData s)
    {
        if (_sessionDetailBody is null) return;
        var section = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        section.Children.Add(new TextBlock { Text = "Session stream", FontSize = 15, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        if (s.State != "active")
        {
            section.Children.Add(Muted("The stream binds to the session: it starts only while the session is active, and dies with it (end / block / STOP / participant removal).", 12));
            _sessionDetailBody.Children.Add(Card(section));
            return;
        }
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        var start = new Button { Content = "Start stream", Style = (Style)FindResource("PrimaryButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        start.Click += async (_, _) => await StartStreamViewerAsync(s.Id);
        row.Children.Add(start);
        var stop = new Button { Content = "Stop stream", Style = (Style)FindResource("GhostButton"), Padding = new Thickness(10, 5, 10, 5) };
        stop.Click += async (_, _) => await StopStreamViewerAsync(s.Id);
        row.Children.Add(stop);
        section.Children.Add(row);
        EnsureStreamPanel();
        section.Children.Add(_streamPanel!);
        _sessionDetailBody.Children.Add(Card(section));
    }

    private void EnsureStreamPanel()
    {
        if (_streamPanel is not null) return;
        _streamPanel = new StackPanel();
        _streamStatus = Muted("Stream not started.", 12);
        _streamPanel.Children.Add(_streamStatus);
        _streamCanvas = new Canvas { Height = 300, Background = new SolidColorBrush(Color.FromRgb(16, 20, 28)) };
        _streamImage = new Image { Stretch = Stretch.Uniform };
        _streamImage.MouseMove += StreamImage_MouseMove;
        _streamImage.MouseDown += StreamImage_MouseDown;
        _streamCanvas.Children.Add(_streamImage);
        _streamCursorChipText = new TextBlock { FontSize = 11, Foreground = Brushes.White, FontWeight = FontWeights.SemiBold };
        _streamCursorChip = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0xCC, 0x1F, 0x6F, 0xEB)),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(6, 2, 6, 2),
            Child = _streamCursorChipText,
            Visibility = Visibility.Collapsed,
        };
        _streamCanvas.Children.Add(_streamCursorChip);
        _streamPanel.Children.Add(_streamCanvas);
        _streamFloorLine = Muted("", 12);
        _streamPanel.Children.Add(_streamFloorLine);
        _streamRosterBody = new StackPanel();
        _streamPanel.Children.Add(_streamRosterBody);
    }

    private string StreamActorId() => _sessionActorBox?.Text.Trim() ?? "";

    private async Task StartStreamViewerAsync(string sessionId)
    {
        EnsureStreamPanel();
        var actor = StreamActorId();
        if (actor.Length == 0)
        {
            _streamStatus!.Text = "Type your actor id in the session surface first — the stream starts as a named participant.";
            return;
        }
        StopStreamLoop();
        _streamSessionId = sessionId;
        _streamSeq = 0;
        _streamDecoder = new H264Decoder();
        try
        {
            var body = JsonSerializer.Serialize(new { sessionId, userId = actor, monitor = 0 });
            using var resp = await StreamHttp.PostAsync($"{StreamBase}/mesh/stream/start",
                new StringContent(body, Encoding.UTF8, "application/json"));
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                _streamStatus!.Text = $"Stream refused ({(int)resp.StatusCode}): {StreamErrorOf(text)}";
                return;
            }
        }
        catch (Exception ex)
        {
            _streamStatus!.Text = $"Stream start failed: {ex.Message}";
            return;
        }
        _streamCts = new CancellationTokenSource();
        _ = StreamLoopAsync(sessionId, _streamCts.Token);
        _streamStatus!.Text = "Stream starting…";
    }

    private async Task StopStreamViewerAsync(string sessionId)
    {
        StopStreamLoop();
        try
        {
            var body = JsonSerializer.Serialize(new { sessionId });
            using var resp = await StreamHttp.PostAsync($"{StreamBase}/mesh/stream/stop",
                new StringContent(body, Encoding.UTF8, "application/json"));
        }
        catch { /* the loop is already stopped locally; the session gate kills the rest */ }
        if (_streamStatus is not null) _streamStatus.Text = "Stream stopped.";
    }

    private void StopStreamLoop()
    {
        try { _streamCts?.Cancel(); } catch { }
        _streamCts = null;
        _streamDecoder?.Dispose();
        _streamDecoder = null;
    }

    private async Task StreamLoopAsync(string sessionId, CancellationToken ct)
    {
        var lastInfo = DateTimeOffset.MinValue;
        var frames = 0;
        var windowStart = DateTimeOffset.UtcNow;
        var fps = 0.0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow - lastInfo > TimeSpan.FromSeconds(2))
                {
                    lastInfo = DateTimeOffset.UtcNow;
                    await RefreshStreamInfoAsync(sessionId, ct);
                    if (_streamSessionId is null) return; // session ended under us
                }
                using var resp = await StreamHttp.GetAsync(
                    $"{StreamBase}/mesh/stream/frame?sessionId={Uri.EscapeDataString(sessionId)}&after={_streamSeq}", ct);
                if (resp.StatusCode == System.Net.HttpStatusCode.NoContent)
                {
                    await Task.Delay(15, ct);
                    continue;
                }
                if (!resp.IsSuccessStatusCode)
                {
                    var text = await resp.Content.ReadAsStringAsync(ct);
                    Dispatcher.Invoke(() =>
                    {
                        if (_streamStatus is not null)
                            _streamStatus.Text = $"Stream ended ({(int)resp.StatusCode}): {StreamErrorOf(text)}";
                    });
                    return;
                }
                var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
                var frame = StreamProtocol.TryParse(bytes);
                if (frame is null)
                {
                    Dispatcher.Invoke(() => { if (_streamStatus is not null) _streamStatus.Text = "Dropped a malformed frame from the stream."; });
                    continue;
                }
                _streamSeq = frame.Header.Seq;
                _streamFrameWidth = frame.Header.Width;
                _streamFrameHeight = frame.Header.Height;
                var decoded = _streamDecoder?.Decode(frame.AccessUnit);
                frames++;
                var elapsed = (DateTimeOffset.UtcNow - windowStart).TotalSeconds;
                if (elapsed >= 2) { fps = frames / elapsed; frames = 0; windowStart = DateTimeOffset.UtcNow; }
                var fpsNow = fps;
                Dispatcher.Invoke(() =>
                {
                    if (_streamStatus is not null)
                        _streamStatus.Text = $"Streaming · seq {_streamSeq} · {frame.Header.Width}×{frame.Header.Height} · {frame.Header.Encoder}{(frame.Header.Hardware ? " (hardware)" : "")} · capture {frame.Header.Capture} · {fpsNow:F1} fps";
                    if (decoded is not null) RenderStreamFrame(decoded.Value, frame.Header);
                });
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => { if (_streamStatus is not null) _streamStatus.Text = $"Stream error: {ex.Message}"; });
                await Task.Delay(500, ct);
            }
        }
    }

    private async Task RefreshStreamInfoAsync(string sessionId, CancellationToken ct)
    {
        try
        {
            using var resp = await StreamHttp.GetAsync(
                $"{StreamBase}/mesh/stream/info?sessionId={Uri.EscapeDataString(sessionId)}", ct);
            if (!resp.IsSuccessStatusCode) { _streamSessionId = null; return; }
            var text = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(text);
            var r = doc.RootElement;
            var sessionState = r.TryGetProperty("sessionState", out var ss) ? ss.GetString() : "";
            var streaming = r.TryGetProperty("streaming", out var st) && st.ValueKind == JsonValueKind.True;
            if (sessionState != "active" || !streaming) { _streamSessionId = null; return; }
            string? holderId = null; string? holderName = null;
            if (r.TryGetProperty("floor", out var fl) && fl.ValueKind == JsonValueKind.Object)
            {
                holderId = fl.TryGetProperty("userId", out var hu) ? hu.GetString() : null;
                holderName = fl.TryGetProperty("name", out var hn) ? hn.GetString() : null;
            }
            var rosterLines = new List<string>();
            if (r.TryGetProperty("roster", out var roster) && roster.ValueKind == JsonValueKind.Array)
                foreach (var p in roster.EnumerateArray())
                    rosterLines.Add($"{p.GetProperty("name").GetString()} — {p.GetProperty("role").GetString()} · floor {p.GetProperty("floor").GetString()}");
            _streamFloorName = holderName;
            Dispatcher.Invoke(() =>
            {
                if (_streamFloorLine is not null)
                    _streamFloorLine.Text = holderId is null
                        ? "Floor: nobody holds the floor — input from this viewer will be refused."
                        : holderId == StreamActorId()
                            ? "Floor: you hold the floor — this viewer's input is live."
                            : $"Floor: {holderName} holds the floor — this viewer's input will be refused by the stream layer.";
                if (_streamRosterBody is not null)
                {
                    _streamRosterBody.Children.Clear();
                    foreach (var line in rosterLines) _streamRosterBody.Children.Add(Muted(line, 12));
                }
            });
        }
        catch { /* info is advisory; the frame loop carries the hard failures */ }
    }

    private void RenderStreamFrame((byte[] Bgra, int Width, int Height) decoded, StreamProtocol.FrameHeader header)
    {
        if (_streamImage is null || _streamCanvas is null) return;
        var bmp = new WriteableBitmap(decoded.Width, decoded.Height, 96, 96, PixelFormats.Bgra32, null);
        bmp.WritePixels(new Int32Rect(0, 0, decoded.Width, decoded.Height), decoded.Bgra, decoded.Width * 4, 0);
        bmp.Freeze();
        _streamImage.Source = bmp;
        _streamImage.Width = _streamCanvas.ActualWidth > 0 ? _streamCanvas.ActualWidth : 640;
        _streamImage.Height = _streamCanvas.Height;
        // Named cursor: the floor holder's chip rides the frame's
        // cursor position (scaled into the rendered picture).
        if (_streamCursorChip is not null && _streamCursorChipText is not null)
        {
            if (_streamFloorName is not null && header.CursorX >= 0 && decoded.Width > 0)
            {
                _streamCursorChipText.Text = _streamFloorName;
                _streamCursorChip.Visibility = Visibility.Visible;
                var x = header.CursorX / (double)decoded.Width * _streamImage.Width;
                var y = header.CursorY / (double)decoded.Height * _streamImage.Height;
                Canvas.SetLeft(_streamCursorChip, Math.Clamp(x, 0, Math.Max(0, _streamImage.Width - 40)));
                Canvas.SetTop(_streamCursorChip, Math.Clamp(y, 0, Math.Max(0, _streamImage.Height - 20)));
            }
            else _streamCursorChip.Visibility = Visibility.Collapsed;
        }
    }

    private (int X, int Y)? StreamPointFromEvent(MouseEventArgs e)
    {
        if (_streamImage is null || _streamFrameWidth == 0 || _streamFrameHeight == 0) return null;
        var pos = e.GetPosition(_streamImage);
        if (_streamImage.ActualWidth <= 0 || _streamImage.ActualHeight <= 0) return null;
        var x = (int)(pos.X / _streamImage.ActualWidth * _streamFrameWidth);
        var y = (int)(pos.Y / _streamImage.ActualHeight * _streamFrameHeight);
        return (Math.Clamp(x, 0, _streamFrameWidth - 1), Math.Clamp(y, 0, _streamFrameHeight - 1));
    }

    private void StreamImage_MouseMove(object sender, MouseEventArgs e)
    {
        if (e.LeftButton != MouseButtonState.Pressed) return;
        var p = StreamPointFromEvent(e);
        if (p is null || _streamSessionId is null) return;
        _ = SendStreamInputAsync(new { type = "pointer_abs", x = p.Value.X, y = p.Value.Y });
    }

    private void StreamImage_MouseDown(object sender, MouseButtonEventArgs e)
    {
        var p = StreamPointFromEvent(e);
        if (p is null || _streamSessionId is null) return;
        _ = SendStreamInputAsync(new { type = "pointer_abs", x = p.Value.X, y = p.Value.Y });
        _ = SendStreamInputAsync(new { type = "button", button = e.ChangedButton == MouseButton.Right ? "right" : "left", action = "click" });
    }

    private async Task SendStreamInputAsync(object eventObj)
    {
        var sessionId = _streamSessionId;
        if (sessionId is null) return;
        try
        {
            var body = JsonSerializer.Serialize(new { sessionId, userId = StreamActorId(), @event = eventObj });
            using var resp = await StreamHttp.PostAsync($"{StreamBase}/mesh/stream/input",
                new StringContent(body, Encoding.UTF8, "application/json"));
            if (!resp.IsSuccessStatusCode)
            {
                var text = await resp.Content.ReadAsStringAsync();
                Dispatcher.Invoke(() =>
                {
                    if (_streamStatus is not null)
                        _streamStatus.Text = $"Input refused ({(int)resp.StatusCode}): {StreamErrorOf(text)}";
                });
            }
        }
        catch { /* refusals are the visible path; transport loss shows in the frame loop */ }
    }

    private static string StreamErrorOf(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() ?? json : json;
        }
        catch { return json; }
    }
}
