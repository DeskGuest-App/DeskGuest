using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Acp.Shared.Ipc;
using Button = System.Windows.Controls.Button;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;

namespace Acp.SessionAgent;

/// <summary>
/// C20 wiring — the Recovery section of the Settings page: the
/// owner-local surface for the recovery blob. Export and restore are
/// acts of the owner at this machine, carried over the authenticated
/// IPC channel (IpcKinds.RecoveryAction) exactly like gate approvals
/// and the vault; there is no agent-callable path (the Core's
/// recovery_blob tool refuses every pairing).
///
/// Key-sheet discipline: the sheet arrives ONCE on the dedicated
/// RecoveryKeySheet message after an export, is shown in this section
/// for the owner to write down, and is never stored by the window —
/// navigating away or exporting again replaces it. It never appears
/// in an action result, the snapshot, or any log.
/// Existing page patterns only; no new design language.
/// </summary>
public partial class MainWindow
{
    private TextBlock? _recoveryStatus;
    private TextBlock? _recoverySheetText;

    /// <summary>The Core's one-time key-sheet answer for an export.</summary>
    public void SetRecoveryKeySheet(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetRecoveryKeySheet(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var sheet = doc.RootElement.GetProperty("keySheet").GetString() ?? "";
            ShowPage("settings");
            if (_recoverySheetText is not null)
            {
                _recoverySheetText.Text =
                    "RECOVERY KEY SHEET — shown once, never stored. Write these 34 words down and keep them with the blob:\n" + sheet;
                _recoverySheetText.Visibility = Visibility.Visible;
            }
            if (_recoveryStatus is not null)
                _recoveryStatus.Text = "Core: export complete — the key sheet is below, shown once.";
        }
        catch { }
    }

    private UIElement BuildRecoverySection()
    {
        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = "Recovery blob", FontSize = 16.5, FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 10, 0, 4)
        });
        body.Children.Add(Muted(
            "Export one encrypted file holding this device's identity, pairings, and roster — you keep it where you choose; there is no cloud copy. " +
            "The export passphrase (10+ characters) and the one-time key sheet each open it. Restore lands only into empty stores: a live identity or any pairing/roster content refuses, loudly, and nothing is overwritten."));
        _recoveryStatus = Muted("");
        body.Children.Add(_recoveryStatus);
        _recoverySheetText = new TextBlock
        {
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 6), Visibility = Visibility.Collapsed
        };
        body.Children.Add(_recoverySheetText);

        Button Ghost(string label) => new()
        {
            Content = label, Style = (Style)FindResource("GhostButton"),
            Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5),
        };
        StackPanel Row() => new() { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };

        // ---- export ----
        var exportPass = new PasswordBox
        {
            Width = 260, Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Export passphrase (at least 10 characters) — never stored"
        };
        var exportRow = Row();
        exportRow.Children.Add(exportPass);
        var exportBtn = Ghost("Export recovery blob…");
        exportBtn.Click += async (_, _) =>
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"acp-recovery-{DateTime.Now:yyyyMMdd-HHmmss}.acprecovery",
                Filter = "ACP recovery blob (*.acprecovery)|*.acprecovery|All files (*.*)|*.*",
                Title = "Export recovery blob"
            };
            if (dialog.ShowDialog(this) != true) return;
            if (_recoverySheetText is not null) _recoverySheetText.Visibility = Visibility.Collapsed;
            await SendHostActionAsync(IpcKinds.RecoveryAction,
                new { action = "export", passphrase = exportPass.Password, outputPath = dialog.FileName }, _recoveryStatus);
            exportPass.Clear();
        };
        exportRow.Children.Add(exportBtn);
        body.Children.Add(exportRow);

        // ---- restore ----
        var restorePass = new PasswordBox
        {
            Width = 260, Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Export passphrase for the blob (or use the key sheet box instead)"
        };
        var restoreRow = Row();
        restoreRow.Children.Add(restorePass);
        var inspectBtn = Ghost("Inspect blob…");
        inspectBtn.Click += async (_, _) =>
        {
            var path = PickRecoveryBlob();
            if (path is null) return;
            await SendHostActionAsync(IpcKinds.RecoveryAction,
                new { action = "inspect", blobPath = path }, _recoveryStatus);
        };
        restoreRow.Children.Add(inspectBtn);
        body.Children.Add(restoreRow);

        var sheetBox = new TextBox
        {
            Width = 520, Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Recovery key sheet (34 words) — the alternative to the passphrase"
        };
        var restoreRow2 = Row();
        restoreRow2.Children.Add(sheetBox);
        var restoreBtn = Ghost("Restore from blob…");
        restoreBtn.Click += async (_, _) =>
        {
            var path = PickRecoveryBlob();
            if (path is null) return;
            await SendHostActionAsync(IpcKinds.RecoveryAction,
                new
                {
                    action = "restore_primary",
                    blobPath = path,
                    passphrase = restorePass.Password.Length > 0 ? restorePass.Password : null,
                    keySheet = sheetBox.Text.Trim().Length > 0 ? sheetBox.Text.Trim() : null
                }, _recoveryStatus);
            restorePass.Clear();
            sheetBox.Clear();
        };
        restoreRow2.Children.Add(restoreBtn);
        body.Children.Add(restoreRow2);
        return Card(body);
    }

    private string? PickRecoveryBlob()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "ACP recovery blob (*.acprecovery)|*.acprecovery|All files (*.*)|*.*",
            Title = "Pick the recovery blob"
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
}
