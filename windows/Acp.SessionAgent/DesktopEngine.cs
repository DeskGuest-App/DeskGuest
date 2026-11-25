using System.Diagnostics;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Forms;
using Acp.Shared.Input;
using Acp.Shared.Policy;
using Acp.Shared.Tools;

namespace Acp.SessionAgent;

/// <summary>
/// The desktop plane's engines (DESIGN §3.2). Every method assumes the
/// Core's policy engine already approved the call; the engine executes
/// and reports honestly. Presence hooks (ghost-cursor glide) fire
/// before every input action — the glide-and-pause is the owner's
/// interruption window (SPEC §7.3). UNPROVEN-ON-WINDOWS until the
/// laptop gate drives it against real applications.
/// </summary>
public sealed class DesktopEngine
{
    private readonly UiaSnapshotService _uia = new();
    private readonly Func<int, int, Task> _glideTo;   // presence ghost cursor
    private readonly Action<string> _narrate;
    private readonly StreamEngine _stream = new();    // Block D session stream pump

    // U7 fail-safe: every key/button this engine holds down is
    // tracked, and ReleaseAllInputs() lets go of all of it. The
    // triggers (IPC disconnect, session end, STOP, revocation) live
    // in AgentIpcClient / CoreRuntime; the release itself is
    // consent-floor — nothing here consults policy before letting go.
    private readonly HeldInputTracker _held = new();
    private readonly IInputReleaseSink _releaseSink;

    public DesktopEngine(Func<int, int, Task> glideTo, Action<string> narrate)
    {
        _glideTo = glideTo;
        _narrate = narrate;
        _releaseSink = new NativeReleaseSink();
    }

    /// <summary>What injected input is currently held down on this
    /// machine (audit-friendly descriptors; empty when clean).</summary>
    public IReadOnlyList<string> HeldInputs => _held.HeldSnapshot();

    /// <summary>Release every held key and mouse button. Fired on
    /// IPC disconnect (link loss), session end, STOP, and pairing
    /// revocation. NOT policy-gated and NOT disableable — a stuck
    /// key on the controlled machine is a safety hazard, and letting
    /// go is always allowed. Returns what was released.</summary>
    public IReadOnlyList<string> ReleaseAllInputs()
    {
        var result = _held.ReleaseAll(_releaseSink);
        if (result.Released.Count > 0)
            _narrate($"Released held input ({string.Join(", ", result.Released)}) — fail-safe");
        // BD-SUPP-HELDINPUT F3: a failed up is SAID, never folded
        // into the released list — and it stays tracked, so the
        // next trigger retries it.
        if (result.Failed.Count > 0)
            _narrate($"Held-input release FAILED for {string.Join(", ", result.Failed)} — still tracked, will retry on the next trigger");
        return result.Released;
    }

    /// <summary>BD-SUPP-HELDINPUT F1/F2: re-arm the held-input
    /// tracker for a new session (a ReleaseAll seals it), and the
    /// startup sweep — ups for every plausible stuck key/button,
    /// run before the agent serves anything, so a predecessor
    /// process killed mid-hold leaves nothing down.</summary>
    public void RearmHeldInputs() => _held.Rearm();

    public IReadOnlyList<string> SweepStuckInputsOnStartup()
    {
        var swept = HeldInputTracker.SweepAllPossible(_releaseSink);
        _held.Rearm();
        return swept;
    }

    /// <summary>The release sink over the real SendInput path: the
    /// ups go out through exactly the sends a normal key_up /
    /// mouse_up tool call would use.</summary>
    private sealed class NativeReleaseSink : IInputReleaseSink, IInputDragCancelSink
    {
        public void ReleaseKey(ushort virtualKey) => SendKeyRaw(virtualKey, down: false);
        public void ReleaseMouseButton(string button) => SendMouseButtonRaw(button, down: false);
        // F11: Esc press cancels an in-progress drag before its
        // button-up can commit it as a modifier-drop.
        public void CancelDrag()
        {
            SendKeyRaw(0x1B, down: true);
            SendKeyRaw(0x1B, down: false);
        }
    }

    // U1: the clipboard policy the Core resolved from TOTAL POLICY
    // CONTROL and pushed over the authenticated IPC channel. The
    // engine enforces it at the clipboard itself — the second wall
    // behind the Core's choke point, for paths that reach the
    // engine without it (batch steps over the channel). Until the
    // first push lands it stands at the named defaults (both
    // directions, sensitive skip ON); a push with the layer toggled
    // off carries ClipboardPolicy.Legacy explicitly, so standing
    // down is a decision the Core states, never a gap.
    private volatile ClipboardPolicy _clipboardPolicy = ClipboardPolicy.Default;

    public ClipboardPolicy CurrentClipboardPolicy => _clipboardPolicy;

    /// <summary>Apply a Core-pushed clipboard policy. A malformed
    /// payload is ignored — the standing instruction stands.</summary>
    public void ApplyClipboardPolicy(string? ipcJson)
    {
        if (ClipboardPolicy.FromIpcJson(ipcJson) is { } policy)
            _clipboardPolicy = policy;
    }

    public UiaSnapshotService Uia => _uia;

    /// <summary>Execute one tool. BD-WIN-AGENT F5: the caller's
    /// cancellation token is the STOP channel — the IPC layer passes
    /// the StopCoordinator's current token, and STOP (Core, local, or
    /// link loss) cancels it. Long-running tools (type_text, wait_for,
    /// shell_exec) observe it; a cancelled tool reports cancelled,
    /// never success.</summary>
    public async Task<(bool Ok, string Text)> ExecuteAsync(string tool, JsonElement args, CancellationToken ct = default)
    {
        try
        {
            return tool switch
            {
                "screenshot" => (true, CapturePngBase64(null)),
                // Mesh companion preview (M2): same capture, JPEG at
                // most 1280px wide — the phone polls this every 2s
                // while its device page is open, so bytes matter.
                "screenshot_jpeg" => (true, CaptureJpegBase64(1280, 75L)),
                // Mesh manual drive (M2): the phone trackpad sends
                // RELATIVE movement and button events at the current
                // position — the owner's own hand, so the REAL cursor
                // moves (no ghost glide; that is for agent actions).
                "mouse_move_rel" => MouseMoveRelative(args),
                "button_here" => ButtonHere(args),
                "screenshot_region" => (true, CapturePngBase64(ReadRect(args))),
                "screenshot_annotated" => (true, CaptureAnnotatedBase64()),
                "snapshot" => (true, _uia.SerializeSnapshot()),
                "display_inventory" => (true, DisplayInventory()),
                "current_window" => (true, CurrentWindow()),
                "wait_for" => await WaitForAsync(args, ct),
                "click" => await ClickAsync(args),
                "type_text" => await TypeTextAsync(args, ct),
                "key_press" => KeyPress(args),
                "shortcut" => KeyPress(args),
                "scroll" => Scroll(args),
                "mouse_move" => await MouseMoveAsync(args),
                "drag" => await DragAsync(args),
                "multi_select" => await MultiSelectAsync(args),
                "multi_edit" => await MultiEditAsync(args),
                "input_primitives" => await InputPrimitivesAsync(args),
                "uia_pattern_action" => PatternAction(args),
                "window_state" => WindowState(args),
                "ui_menu_dialog" => await MenuDialogAsync(args),
                "app_launch" => AppLaunch(args),
                "app_switch" => AppSwitch(args),
                "window_focus" => AppSwitch(args),
                "open_url" => OpenUrl(args),
                "clipboard_get" => ClipboardGet(),
                "clipboard_set" => ClipboardSet(args),
                "shell_exec" => await ShellExecAsync(args, ct),
                "session_lock" => LockSession(),
                // Block D real session stream: the Core's
                // StreamService drives the pump through these tools;
                // frames cross IPC as base64 ACPF envelopes and the
                // Core re-validates every envelope before serving it.
                "stream_start" => _stream.Start(GetInt(args, "monitor")),
                "stream_frame" => _stream.GetFrame(GetLong(args, "after")),
                "stream_stop" => _stream.Stop(),
                "stream_monitors" => (true, StreamEngine.MonitorsJson()),
                "stream_stats" => (true, _stream.StatsJson()),
                // Absolute pointer placement for stream viewers:
                // x/y are pixel coordinates inside the streamed
                // monitor; the engine offsets them to the virtual
                // desktop. Moves the real cursor (a floor holder's
                // hand, same rule as mouse_move_rel).
                "mouse_move_abs_stream" => MouseMoveAbsoluteStream(args),
                "ocr_text" => await OcrAsync(args),
                "touch_gesture" => (false, "touch input requires a touch display; InjectTouchInput path is Phase 2-gated on this host"),
                _ => (false, $"the session agent does not implement '{tool}'")
            };
        }
        catch (OperationCanceledException)
        {
            // BD-WIN-AGENT F5: STOP (or link loss) cancelled the tool
            // mid-flight. Report exactly that — never a fake success.
            return (false, "cancelled: STOP interrupted this tool before it finished");
        }
        catch (Exception ex)
        {
            // FR-112 (W65): surface the REAL exception chain — type,
            // message, and the inner exception when present — never
            // a bare generic. (The W58 snapshot failure reached the
            // agent as an unexplained engine error; the root
            // exception must be visible in the product's own output.)
            var inner = ex.InnerException is null ? "" : $" [inner {ex.InnerException.GetType().Name}: {ex.InnerException.Message}]";
            return (false, $"desktop engine error ({ex.GetType().Name}): {ex.Message}{inner}");
        }
    }

    /// <summary>BD-WIN-AGENT F7: the ONE credential-field probe for
    /// keyboard injection. Returns true (with the refusal text) when
    /// typing must NOT proceed: the focused element IS a password
    /// field, or its state could not be verified — X1 fails closed,
    /// because the fields where UIA throws are exactly the hardened
    /// credential fields the rule exists for.</summary>
    private static bool FocusBlocksTyping(out string refusal)
    {
        try
        {
            var focused = AutomationElement.FocusedElement;
            if (focused is not null && focused.GetCurrentPropertyValue(AutomationElement.IsPasswordProperty) is true)
            {
                refusal = "refused: the focused field is a password field; agents never type credentials (ACP §7.4)";
                return true;
            }
            refusal = "";
            return false;
        }
        catch
        {
            refusal = "refused: the focused field's credential state could not be verified, so nothing was typed (X1 fails closed — ACP §7.4)";
            return true;
        }
    }

    /// <summary>BD-WIN-AGENT F8: the one agent-originated pointer
    /// injection path — narration + ghost-cursor glide (the user's
    /// interruption window) BEFORE the button moves. Every agent
    /// click routes through here; the glide-free path remains only
    /// for the floor holder's own manual-drive tools.</summary>
    private async Task InjectClickAtAsync(int x, int y, string button, string narration)
    {
        _narrate(narration);
        await _glideTo(x, y);
        MouseButton(button, down: true); MouseButton(button, down: false);
    }

    // ---------- Perception ----------

    private static string CapturePngBase64(Rectangle? region)
    {
        var bounds = region ?? SystemInformation.VirtualScreen;
        using var bmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp))
            g.CopyFromScreen(bounds.Left, bounds.Top, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);
        return ToBase64(bmp);
    }

    private string CaptureAnnotatedBase64()
    {
        var bounds = SystemInformation.VirtualScreen;
        using var bmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp))
        {
            g.CopyFromScreen(bounds.Left, bounds.Top, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);
            using var pen = new Pen(Color.Magenta, 2);
            using var font = new Font("Segoe UI", 10, System.Drawing.FontStyle.Bold);
            foreach (var (label, rect) in _uia.InteractiveElements())
            {
                var r = new Rectangle((int)rect.X - bounds.Left, (int)rect.Y - bounds.Top, (int)rect.Width, (int)rect.Height);
                g.DrawRectangle(pen, r);
                g.DrawString(label, font, Brushes.Magenta, r.Left, Math.Max(0, r.Top - 14));
            }
        }
        return ToBase64(bmp);
    }

    private static string ToBase64(Bitmap bmp)
    {
        using var ms = new MemoryStream();
        bmp.Save(ms, ImageFormat.Png);
        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>JPEG capture for the mesh preview: full virtual
    /// screen, downscaled to <paramref name="maxWidth"/> keeping
    /// aspect, encoded at the given quality. Base64 in the text
    /// slot, same as the PNG path.</summary>
    private static string CaptureJpegBase64(int maxWidth, long quality)
    {
        var bounds = SystemInformation.VirtualScreen;
        using var full = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(full))
            g.CopyFromScreen(bounds.Left, bounds.Top, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);
        var scale = Math.Min(1.0, (double)maxWidth / bounds.Width);
        var w = Math.Max(1, (int)(bounds.Width * scale));
        var h = Math.Max(1, (int)(bounds.Height * scale));
        using var scaled = new Bitmap(full, new System.Drawing.Size(w, h));
        using var ms = new MemoryStream();
        var codec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
        using var parameters = new EncoderParameters(1);
        parameters.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, quality);
        scaled.Save(ms, codec, parameters);
        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>Relative pointer movement for the phone trackpad:
    /// dx/dy are fractions of the pad's width/height; a full-width
    /// swipe travels 75% of the screen. Moves the real cursor —
    /// manual drive is the user's own hand.</summary>
    private static (bool, string) MouseMoveRelative(JsonElement args)
    {
        var dx = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("dx", out var dxEl) && dxEl.ValueKind == JsonValueKind.Number ? dxEl.GetDouble() : 0;
        var dy = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("dy", out var dyEl) && dyEl.ValueKind == JsonValueKind.Number ? dyEl.GetDouble() : 0;
        if (!NativeMethods.GetCursorPos(out var pos)) return (false, "could not read the cursor position");
        var screen = SystemInformation.VirtualScreen;
        var nx = Math.Clamp(pos.X + (int)Math.Round(dx * screen.Width * 0.75), screen.Left, screen.Right - 1);
        var ny = Math.Clamp(pos.Y + (int)Math.Round(dy * screen.Height * 0.75), screen.Top, screen.Bottom - 1);
        NativeMethods.SetCursorPos(nx, ny);
        return (true, $"{{\"x\":{nx},\"y\":{ny}}}");
    }

    private static (bool, string) MouseMoveAbsoluteStream(JsonElement args)
    {
        var x = GetInt(args, "x"); var y = GetInt(args, "y");
        var monitor = GetInt(args, "monitor");
        var monitors = StreamEngine.MonitorsJson();
        using var doc = JsonDocument.Parse(monitors);
        var list = doc.RootElement.EnumerateArray().ToList();
        if (monitor < 0 || monitor >= list.Count) return (false, $"monitor {monitor} does not exist");
        var m = list[monitor];
        var ox = m.GetProperty("x").GetInt32(); var oy = m.GetProperty("y").GetInt32();
        var w = m.GetProperty("width").GetInt32(); var h = m.GetProperty("height").GetInt32();
        var nx = ox + Math.Clamp(x, 0, Math.Max(0, w - 1));
        var ny = oy + Math.Clamp(y, 0, Math.Max(0, h - 1));
        NativeMethods.SetCursorPos(nx, ny);
        return (true, $"{{\"x\":{nx},\"y\":{ny}}}");
    }

    private static long GetLong(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : 0;

    /// <summary>A mouse button event at the current cursor position
    /// (mesh manual drive): action is click (down+up), down, or up.
    /// A bare "down" is a deliberate hold — tracked like every other
    /// hold (U7), so a dead link mid-hold still gets its release.</summary>
    private (bool, string) ButtonHere(JsonElement args)
    {
        var button = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("button", out var b) ? b.GetString() ?? "left" : "left";
        var action = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("action", out var a) ? a.GetString() ?? "click" : "click";
        switch (action)
        {
            case "down": MouseButton(button, true); break;
            case "up": MouseButton(button, false); break;
            default: MouseButton(button, true); MouseButton(button, false); break;
        }
        return (true, "ok");
    }

    private static Rectangle? ReadRect(JsonElement args) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty("x", out _)
            ? new Rectangle(GetInt(args, "x"), GetInt(args, "y"), GetInt(args, "width", 400), GetInt(args, "height", 300))
            : null;

    private static string DisplayInventory()
    {
        var screens = Screen.AllScreens.Select((s, i) => new
        {
            index = i,
            primary = s.Primary,
            x = s.Bounds.X, y = s.Bounds.Y, width = s.Bounds.Width, height = s.Bounds.Height,
            working_width = s.WorkingArea.Width, working_height = s.WorkingArea.Height
        });
        return JsonSerializer.Serialize(screens, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string CurrentWindow()
    {
        var hwnd = NativeMethods.GetForegroundWindow();
        try
        {
            var el = AutomationElement.FromHandle(hwnd);
            return JsonSerializer.Serialize(new
            {
                name = el.Current.Name,
                process = Process.GetProcessById(el.Current.ProcessId).ProcessName,
                control_type = el.Current.ControlType?.ProgrammaticName
            });
        }
        catch
        {
            return JsonSerializer.Serialize(new { name = "", process = "", note = "foreground window not readable via UIA" });
        }
    }

    private async Task<(bool, string)> WaitForAsync(JsonElement args, CancellationToken ct)
    {
        var text = GetString(args, "text");
        var timeoutSec = GetInt(args, "timeout_seconds", 10);
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(timeoutSec);
        // BD-WIN-AGENT F11: poll with backoff (250 ms → 1 s) instead
        // of hammering a full UIA walk four times a second; F5: the
        // STOP token ends the wait immediately. FindByText no longer
        // invalidates the agent's snapshot refs (see UiaSnapshot).
        var delayMs = 250;
        while (DateTimeOffset.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (text is not null && _uia.FindByText(text) is not null)
                return (true, $"found '{text}'");
            await Task.Delay(delayMs, ct);
            delayMs = Math.Min(delayMs * 2, 1000);
        }
        return (false, $"timeout: '{text}' did not appear within {timeoutSec}s (reported, not pretended)");
    }

    // ---------- Input ----------

    private async Task<(bool, string)> ClickAsync(JsonElement args)
    {
        int x, y;
        if (args.TryGetProperty("element_ref", out var refEl))
        {
            var el = _uia.Resolve(refEl.GetString() ?? "");
            if (el is null) return (false, "stale element ref: take a fresh snapshot (refs are snapshot-scoped)");
            var r = el.Current.BoundingRectangle;
            x = (int)(r.Left + r.Width / 2); y = (int)(r.Top + r.Height / 2);
        }
        else { x = GetInt(args, "x"); y = GetInt(args, "y"); }

        var button = GetString(args, "button") ?? "left";
        var dbl = args.TryGetProperty("double", out var d) && d.ValueKind == JsonValueKind.True;
        // BD-WIN-AGENT F8: clicks go through the one glide+narrate path.
        await InjectClickAtAsync(x, y, button, $"Clicking at {x},{y}");
        if (dbl) { MouseButton(button, down: true); MouseButton(button, down: false); }
        return (true, $"clicked {button} at {x},{y}");
    }

    private async Task<(bool, string)> TypeTextAsync(JsonElement args, CancellationToken ct = default)
    {
        var text = GetString(args, "text") ?? "";
        // X1 at the point of action too: if the focused element is a
        // credential field, refuse — defence in depth behind the policy
        // engine's refusal (the engine cannot see the live focus).
        // FAIL CLOSED (second-inspector H2): if the credential-field
        // check cannot run, we do not type.
        if (FocusBlocksTyping(out var refusal)) return (false, refusal);

        _narrate($"Typing {text.Length} characters");
        foreach (var ch in text)
        {
            // BD-WIN-AGENT F5: STOP ends the typing mid-string.
            ct.ThrowIfCancellationRequested();
            var inputs = new[]
            {
                new NativeMethods.INPUT { type = NativeMethods.INPUT_KEYBOARD, U = new NativeMethods.InputUnion { ki = new NativeMethods.KEYBDINPUT { wScan = ch, dwFlags = NativeMethods.KEYEVENTF_UNICODE } } },
                new NativeMethods.INPUT { type = NativeMethods.INPUT_KEYBOARD, U = new NativeMethods.InputUnion { ki = new NativeMethods.KEYBDINPUT { wScan = ch, dwFlags = NativeMethods.KEYEVENTF_UNICODE | NativeMethods.KEYEVENTF_KEYUP } } }
            };
            NativeMethods.SendInput(2, inputs, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.INPUT>());
        }
        await Task.CompletedTask;
        return (true, $"typed {text.Length} characters");
    }

    private (bool, string) KeyPress(JsonElement args)
    {
        var keys = GetString(args, "keys") ?? "";
        // BD-WIN-AGENT F7: the chord is parsed into a canonical VK
        // set by the ONE guard — order and spelling variants
        // ("alt+ctrl+del", "control+alt+delete", "l+win") are the
        // same combo to it. The pre-fix substring match refused only
        // two literal spellings and never checked password focus, so
        // single letters and ctrl+v typed into credential fields.
        var chord = InputGuard.ParseChord(keys);
        if (chord is null) return (false, $"unknown key in '{keys}'");
        if (InputGuard.IsForbiddenCombo(chord))
            return (false, "refused: SAS-class and lock combos can never be injected (platform rule, X19)");
        if (InputGuard.NeedsCredentialFieldCheck(chord) && FocusBlocksTyping(out var refusal))
            return (false, refusal);
        _narrate($"Pressing {keys}");
        var pressed = new List<ushort>();
        foreach (var vk in chord)
        {
            if (!SendKeyGuarded(vk, down: true))
            {
                foreach (var p in pressed.AsEnumerable().Reverse()) SendKey(p, down: false);
                return (false, $"refused: '{keys}' was blocked by the input guard partway (X19/X1)");
            }
            pressed.Add(vk);
        }
        foreach (var vk in pressed.AsEnumerable().Reverse()) SendKey(vk, down: false);
        return (true, $"pressed {keys}");
    }

    private (bool, string) Scroll(JsonElement args)
    {
        var delta = GetInt(args, "delta", -120);
        // BD-WIN-AGENT F8: scroll actions narrate like every other
        // agent action (the pre-fix path injected silently).
        _narrate($"Scrolling {delta}");
        var input = new NativeMethods.INPUT
        {
            type = NativeMethods.INPUT_MOUSE,
            U = new NativeMethods.InputUnion { mi = new NativeMethods.MOUSEINPUT { dwFlags = NativeMethods.MOUSEEVENTF_WHEEL, mouseData = unchecked((uint)delta) } }
        };
        NativeMethods.SendInput(1, new[] { input }, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.INPUT>());
        return (true, $"scrolled {delta}");
    }

    private async Task<(bool, string)> MouseMoveAsync(JsonElement args)
    {
        var x = GetInt(args, "x"); var y = GetInt(args, "y");
        await _glideTo(x, y);
        return (true, $"cursor at {x},{y}");
    }

    private async Task<(bool, string)> DragAsync(JsonElement args)
    {
        var (x1, y1, x2, y2) = (GetInt(args, "from_x"), GetInt(args, "from_y"), GetInt(args, "to_x"), GetInt(args, "to_y"));
        await _glideTo(x1, y1);
        MouseButton("left", true);
        try { await _glideTo(x2, y2); }
        finally { MouseButton("left", false); } // a drag owns its hold: a glide failure mid-drag never leaves the button down (U7)
        return (true, $"dragged {x1},{y1} → {x2},{y2}");
    }

    private async Task<(bool, string)> MultiSelectAsync(JsonElement args)
    {
        if (!args.TryGetProperty("points", out var pts) || pts.ValueKind != JsonValueKind.Array)
            return (false, "multi_select requires {points:[{x,y},...]}");
        SendKey(0x11, true); // CTRL down
        // BD-WIN-AGENT F8 residual: multi-select narrates like every
        // other agent action (its per-point glides already fire).
        _narrate($"Multi-selecting {pts.GetArrayLength()} points");
        try
        {
            foreach (var p in pts.EnumerateArray())
            {
                await _glideTo(GetInt(p, "x"), GetInt(p, "y"));
                MouseButton("left", true); MouseButton("left", false);
            }
        }
        finally { SendKey(0x11, false); } // CTRL is this call's own hold: never outlive the call (U7)
        return (true, "multi-select complete");
    }

    private async Task<(bool, string)> MultiEditAsync(JsonElement args)
    {
        if (!args.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Array)
            return (false, "multi_edit requires {fields:[{element_ref,text},...]}");
        foreach (var f in fields.EnumerateArray())
        {
            var el = _uia.Resolve(GetString(f, "element_ref") ?? "");
            if (el is null) return (false, "stale element ref in multi_edit: take a fresh snapshot");
            if (el.GetCurrentPropertyValue(AutomationElement.IsPasswordProperty) is true)
                return (false, "refused: a target field is a password field (ACP §7.4)");
            el.SetFocus();
            if (el.TryGetCurrentPattern(ValuePattern.Pattern, out var vp))
                ((ValuePattern)vp).SetValue(GetString(f, "text") ?? "");
            else
            {
                var clickArgs = JsonDocument.Parse($"{{\"x\":{(int)el.Current.BoundingRectangle.Left + 4},\"y\":{(int)el.Current.BoundingRectangle.Top + 4}}}").RootElement;
                await ClickAsync(clickArgs);
                await TypeTextAsync(JsonDocument.Parse(JsonSerializer.Serialize(new { text = GetString(f, "text") ?? "" })).RootElement);
            }
        }
        return (true, "multi-edit complete");
    }

    private async Task<(bool, string)> InputPrimitivesAsync(JsonElement args)
    {
        var action = GetString(args, "action") ?? "";
        switch (action)
        {
            // BD-WIN-AGENT F8: primitives narrate + glide like every
            // agent action (glide target = current cursor position;
            // the glide is the user's interruption window even when
            // the pointer does not travel).
            case "mouse_down":
                _narrate("Mouse button down");
                if (NativeMethods.GetCursorPos(out var md)) await _glideTo(md.X, md.Y);
                MouseButton(GetString(args, "button") ?? "left", true); return (true, "mouse down");
            case "mouse_up":
                _narrate("Mouse button up");
                MouseButton(GetString(args, "button") ?? "left", false); return (true, "mouse up");
            case "key_down":
            {
                // BD-WIN-AGENT F7: key_down goes through the guard —
                // the pre-fix path had NO check, so a forbidden combo
                // could be assembled one key at a time and text could
                // be typed into a focused password field.
                var keyName = GetString(args, "key") ?? "";
                var vk = InputGuard.VirtualKeyFor(keyName);
                if (vk == 0) return (false, $"unknown key '{keyName}'");
                if (InputGuard.WouldCompleteForbiddenCombo(_held.HeldKeys(), vk))
                    return (false, "refused: this key completes a SAS-class or lock combo (platform rule, X19)");
                if (InputGuard.NeedsCredentialFieldCheck(new[] { vk }) && FocusBlocksTyping(out var refusal))
                    return (false, refusal);
                _narrate($"Key down: {keyName}");
                SendKey(vk, true); return (true, "key down");
            }
            case "key_up": SendKey(Vk(GetString(args, "key") ?? ""), false); return (true, "key up");
            case "triple_click":
                if (NativeMethods.GetCursorPos(out var tc))
                    await InjectClickAtAsync(tc.X, tc.Y, "left", "Triple-clicking");
                else { MouseButton("left", true); MouseButton("left", false); }
                for (var i = 0; i < 2; i++) { MouseButton("left", true); MouseButton("left", false); }
                return (true, "triple-clicked");
            case "cursor_position":
                NativeMethods.GetCursorPos(out var pt);
                return (true, JsonSerializer.Serialize(new { x = pt.X, y = pt.Y }));
            default:
                return (false, $"unknown input primitive '{action}'");
        }
    }

    private (bool, string) PatternAction(JsonElement args)
    {
        var el = _uia.Resolve(GetString(args, "element_ref") ?? "");
        if (el is null) return (false, "stale element ref: take a fresh snapshot");
        var action = GetString(args, "action") ?? "";
        try
        {
            switch (action)
            {
                case "invoke" when el.TryGetCurrentPattern(InvokePattern.Pattern, out var ip):
                    ((InvokePattern)ip).Invoke(); return (true, "invoked");
                case "set_value" when el.TryGetCurrentPattern(ValuePattern.Pattern, out var vp):
                    if (el.GetCurrentPropertyValue(AutomationElement.IsPasswordProperty) is true)
                        return (false, "refused: password field (ACP §7.4)");
                    ((ValuePattern)vp).SetValue(GetString(args, "value") ?? ""); return (true, "value set");
                case "toggle" when el.TryGetCurrentPattern(TogglePattern.Pattern, out var tp):
                    ((TogglePattern)tp).Toggle(); return (true, "toggled");
                case "select" when el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var sp):
                    ((SelectionItemPattern)sp).Select(); return (true, "selected");
                case "expand" when el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var ep1):
                    ((ExpandCollapsePattern)ep1).Expand(); return (true, "expanded");
                case "collapse" when el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var ep2):
                    ((ExpandCollapsePattern)ep2).Collapse(); return (true, "collapsed");
                case "focus":
                    el.SetFocus(); return (true, "focused");
                default:
                    return (false, $"pattern action '{action}' is not supported by this element");
            }
        }
        catch (Exception ex) { return (false, $"pattern action failed: {ex.Message}"); }
    }

    // ---------- Windows & apps ----------

    /// <summary>BD-WIN-AGENT F9: the window handle for an element —
    /// its own when it has one, else the nearest ancestor's. Zero
    /// when no ancestor owns a window: the caller must fail honestly
    /// instead of passing 0 to Win32 and reporting success.</summary>
    private static IntPtr ResolveWindowHandle(AutomationElement el)
    {
        var current = el;
        for (var hop = 0; hop < 32 && current is not null; hop++)
        {
            try
            {
                var hwnd = new IntPtr(current.Current.NativeWindowHandle);
                if (hwnd != IntPtr.Zero) return hwnd;
                current = TreeWalker.RawViewWalker.GetParent(current);
            }
            catch { return IntPtr.Zero; }
        }
        return IntPtr.Zero;
    }

    private (bool, string) WindowState(JsonElement args)
    {
        var el = _uia.Resolve(GetString(args, "element_ref") ?? "");
        if (el is null) return (false, "stale element ref: take a fresh snapshot");
        // BD-WIN-AGENT F9: never call Win32 with a zero handle and
        // report success for it.
        var hwnd = ResolveWindowHandle(el);
        if (hwnd == IntPtr.Zero)
            return (false, "the element and its ancestors have no window handle; nothing was done");
        var action = GetString(args, "action") ?? "";
        switch (action)
        {
            case "minimize": NativeMethods.ShowWindow(hwnd, 6); break;
            case "maximize": NativeMethods.ShowWindow(hwnd, 3); break;
            case "restore": NativeMethods.ShowWindow(hwnd, 9); break;
            case "bring_to_front":
                if (!NativeMethods.SetForegroundWindow(hwnd))
                    return (false, "Windows refused to bring the window to the front (foreground lock); it was NOT focused");
                break;
            case "move":
            case "resize":
                var r = el.Current.BoundingRectangle;
                if (!NativeMethods.MoveWindow(hwnd,
                    args.TryGetProperty("x", out var xv) ? xv.GetInt32() : (int)r.X,
                    args.TryGetProperty("y", out var yv) ? yv.GetInt32() : (int)r.Y,
                    args.TryGetProperty("width", out var wv) ? wv.GetInt32() : (int)r.Width,
                    args.TryGetProperty("height", out var hv) ? hv.GetInt32() : (int)r.Height, true))
                    return (false, $"window {action} failed (MoveWindow refused)");
                break;
            case "close":
                // BD-WIN-AGENT F9: close means CLOSE. The pre-fix
                // code hid the window (SW_HIDE) and reported
                // "window close applied" — the app kept running,
                // invisible to the user. WM_CLOSE asks the window to
                // close through its normal path.
                if (!NativeMethods.PostMessage(hwnd, NativeMethods.WM_CLOSE, IntPtr.Zero, IntPtr.Zero))
                    return (false, "window close failed (WM_CLOSE could not be posted)");
                return (true, "window close requested (WM_CLOSE posted)");
            default: return (false, $"unknown window_state action '{action}'");
        }
        return (true, $"window {action} applied");
    }

    private async Task<(bool, string)> MenuDialogAsync(JsonElement args)
    {
        var itemName = GetString(args, "item") ?? "";
        var el = _uia.FindByText(itemName);
        if (el is null) return (false, $"menu item '{itemName}' not found in the current UI tree");
        if (el.TryGetCurrentPattern(InvokePattern.Pattern, out var ip)) { ((InvokePattern)ip).Invoke(); return (true, $"invoked '{itemName}'"); }
        if (el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var ep)) { ((ExpandCollapsePattern)ep).Expand(); return (true, $"expanded '{itemName}'"); }
        var r = el.Current.BoundingRectangle;
        // BD-WIN-AGENT F8: the fallback click goes through the one
        // glide+narrate path — the pre-fix code teleported the real
        // cursor with SetCursorPos and clicked silently.
        await InjectClickAtAsync((int)(r.Left + r.Width / 2), (int)(r.Top + r.Height / 2), "left", $"Clicking menu item '{itemName}'");
        return (true, $"clicked '{itemName}'");
    }

    private (bool, string) AppLaunch(JsonElement args)
    {
        var path = GetString(args, "path") ?? GetString(args, "name");
        if (string.IsNullOrWhiteSpace(path)) return (false, "app_launch requires {path} or {name}");
        var psi = new ProcessStartInfo(path)
        {
            Arguments = GetString(args, "arguments") ?? "",
            WorkingDirectory = GetString(args, "working_directory") ?? "",
            UseShellExecute = true
        };
        Process.Start(psi);
        return (true, $"launched {path}");
    }

    private (bool, string) AppSwitch(JsonElement args)
    {
        var title = GetString(args, "title") ?? GetString(args, "name") ?? "";
        var el = _uia.FindByText(title);
        if (el is null) return (false, $"no window matching '{title}'");
        // BD-WIN-AGENT F9: same handle honesty as WindowState.
        var hwnd = ResolveWindowHandle(el);
        if (hwnd == IntPtr.Zero)
            return (false, $"'{title}' and its ancestors have no window handle; nothing was focused");
        if (!NativeMethods.SetForegroundWindow(hwnd))
            return (false, $"Windows refused to focus '{title}' (foreground lock); it was NOT focused");
        return (true, $"focused '{title}'");
    }

    private (bool, string) OpenUrl(JsonElement args)
    {
        var url = GetString(args, "url") ?? "";
        // BD-WIN-AGENT F10: open_url is a browser act (http/https/
        // mailto only). The pre-fix code ShellExecuted ANY string —
        // files, programs and protocol handlers — making open_url
        // an unrestricted app_launch under a lighter scope.
        if (OpenUrlPolicy.RefusalFor(url) is { } refusal) return (false, refusal);
        Process.Start(new ProcessStartInfo(url.Trim()) { UseShellExecute = true });
        return (true, $"opened {url}");
    }

    // ---------- Clipboard / shell / lock / OCR ----------

    private (bool, string) ClipboardGet()
    {
        // U1 at the real clipboard path: direction first (a
        // forbidden direction never touches the clipboard), then
        // the sensitive skip over the actual clip text — on a hit
        // the refusal names the classifier class and the content
        // never leaves this method. A permitted read narrates on
        // the banner as it happens (per-read indicator).
        var policy = _clipboardPolicy;
        if (policy.DenyReasonFor("clipboard_get") is { } denied)
            return (false, denied);
        var text = System.Windows.Clipboard.ContainsText() ? System.Windows.Clipboard.GetText() : "";
        var (ok, refusal) = ClipboardGate.CheckRead(policy, text);
        if (!ok)
        {
            _narrate($"Clipboard read refused — {refusal}");
            return (false, refusal!);
        }
        _narrate($"Clipboard read by the agent ({text.Length} chars)");
        return (true, text);
    }

    private (bool, string) ClipboardSet(JsonElement args)
    {
        var (ok, refusal) = ClipboardGate.CheckWrite(_clipboardPolicy);
        if (!ok) return (false, refusal!);
        // BD-WIN-AGENT F7: staging clipboard text while a password
        // field is focused sets up the unchecked ctrl+v into the
        // credential field — refuse at the staging point too (X1,
        // fail closed), the mirror of the paste-chord check in
        // KeyPress.
        if (FocusBlocksTyping(out var focusRefusal)) return (false, focusRefusal);
        var text = GetString(args, "text") ?? "";
        System.Windows.Clipboard.SetText(text);
        _narrate($"Clipboard set by the agent ({text.Length} chars)");
        return (true, "clipboard set");
    }

    private async Task<(bool, string)> ShellExecAsync(JsonElement args, CancellationToken ct)
    {
        // Census row 27: shell as the owner — this process IS the owner's context.
        var command = GetString(args, "command") ?? "";
        // BD-WIN-AGENT F5: shell_exec gets a deadline (default 60 s,
        // arg-clamped) and STOP cancels it — the pre-fix code had NO
        // timeout at all. stdout and stderr drain CONCURRENTLY: the
        // pre-fix sequential reads deadlocked whenever the child
        // filled the stderr pipe while stdout stayed open. On
        // timeout or STOP the whole process TREE is killed.
        var timeoutSec = Math.Clamp(GetInt(args, "timeout_seconds", 60), 1, 600);
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSec));
        try
        {
            var stdoutTask = p.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderrTask = p.StandardError.ReadToEndAsync(deadline.Token);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            await p.WaitForExitAsync(deadline.Token);
            return (p.ExitCode == 0, JsonSerializer.Serialize(new { exit_code = p.ExitCode, stdout, stderr, execution_context = $"Owner ({Environment.UserName})" }));
        }
        catch (OperationCanceledException)
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
            var stopped = ct.IsCancellationRequested;
            return (false, stopped
                ? "shell_exec cancelled by STOP; the process tree was killed"
                : $"shell_exec timed out after {timeoutSec}s; the process tree was killed");
        }
    }

    private (bool, string) LockSession()
    {
        NativeMethods.LockWorkStation();
        return (true, "workstation lock requested");
    }

    private async Task<(bool, string)> OcrAsync(JsonElement args)
    {
        // Census row 92: OCR via Tesseract where installed; honest
        // unavailable where it isn't. (Windows.Media.Ocr via CsWinRT is
        // the Phase 2 engine swap; the tool contract is identical.)
        var tesseract = new[] { @"C:\Program Files\Tesseract-OCR\tesseract.exe", "tesseract.exe" }
            .FirstOrDefault(p => p == "tesseract.exe" || File.Exists(p));
        if (tesseract is null) return (false, "OCR unavailable: Tesseract is not installed on this host");
        var png = CapturePngBase64(ReadRect(args));
        var tmp = Path.Combine(Path.GetTempPath(), $"acp-ocr-{Guid.NewGuid():N}.png");
        await File.WriteAllBytesAsync(tmp, Convert.FromBase64String(png));
        try
        {
            var psi = new ProcessStartInfo(tesseract, $"\"{tmp}\" stdout --psm 6") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            var text = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (true, text);
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    // ---------- Low-level helpers ----------

    /// <summary>Tracked button send (U7 + BD-SUPP-HELDINPUT F1):
    /// a DOWN goes through the tracker's atomic press — recorded
    /// under the gate BEFORE the raw send, so a racing ReleaseAll
    /// either releases it or has sealed the tracker, in which case
    /// no down is sent at all. The pre-fix order (send, then note)
    /// left a window where a button was physically down but
    /// untracked. Ups are never gated: releasing is always allowed.</summary>
    private void MouseButton(string button, bool down)
    {
        if (down)
            _held.PressButton(button, () => SendMouseButtonRaw(button, true), () => SendMouseButtonRaw(button, false));
        else { SendMouseButtonRaw(button, false); _held.NoteMouseUp(button); }
    }

    /// <summary>Tracked key send (U7 + BD-SUPP-HELDINPUT F1):
    /// same atomic-press rule as MouseButton.</summary>
    private void SendKey(ushort vk, bool down)
    {
        if (down)
            _held.PressKey(vk, () => SendKeyRaw(vk, true), () => SendKeyRaw(vk, false));
        else { SendKeyRaw(vk, false); _held.NoteKeyUp(vk); }
    }

    /// <summary>BD-WIN-AGENT F7: a key-DOWN send through the central
    /// guard — refuses (sends nothing, returns false) when this key,
    /// combined with what is already held, completes a forbidden
    /// X19 combo. Key-ups are never guarded: releasing is always
    /// allowed (the consent-floor rule).</summary>
    private bool SendKeyGuarded(ushort vk, bool down)
    {
        if (down && InputGuard.WouldCompleteForbiddenCombo(_held.HeldKeys(), vk)) return false;
        SendKey(vk, down);
        return true;
    }

    private static void SendMouseButtonRaw(string button, bool down)
    {
        var flag = (button, down) switch
        {
            ("left", true) => NativeMethods.MOUSEEVENTF_LEFTDOWN,
            ("left", false) => NativeMethods.MOUSEEVENTF_LEFTUP,
            ("right", true) => NativeMethods.MOUSEEVENTF_RIGHTDOWN,
            ("right", false) => NativeMethods.MOUSEEVENTF_RIGHTUP,
            ("middle", true) => NativeMethods.MOUSEEVENTF_MIDDLEDOWN,
            ("middle", false) => NativeMethods.MOUSEEVENTF_MIDDLEUP,
            _ => NativeMethods.MOUSEEVENTF_LEFTDOWN
        };
        var input = new NativeMethods.INPUT { type = NativeMethods.INPUT_MOUSE, U = new NativeMethods.InputUnion { mi = new NativeMethods.MOUSEINPUT { dwFlags = flag } } };
        NativeMethods.SendInput(1, new[] { input }, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.INPUT>());
    }

    private static void SendKeyRaw(ushort vk, bool down)
    {
        if (vk == 0) return;
        var input = new NativeMethods.INPUT
        {
            type = NativeMethods.INPUT_KEYBOARD,
            U = new NativeMethods.InputUnion { ki = new NativeMethods.KEYBDINPUT { wVk = vk, dwFlags = down ? 0 : NativeMethods.KEYEVENTF_KEYUP } }
        };
        NativeMethods.SendInput(1, new[] { input }, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.INPUT>());
    }

    // BD-WIN-AGENT F7: key-name resolution is the guard's ONE map —
    // the engine's private copy accepted fewer spellings than agents
    // emit ("control", "delete", "windows"), which is how variant
    // spellings slipped the old substring checks.
    private static ushort Vk(string key) => InputGuard.VirtualKeyFor(key);

    private static string? GetString(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int GetInt(JsonElement args, string name, int fallback = 0) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : fallback;
}
