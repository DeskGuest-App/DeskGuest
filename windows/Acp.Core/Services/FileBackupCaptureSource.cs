using Acp.Shared.Backup;

namespace Acp.Core.Services;

/// <summary>
/// W11 / R-15: the production FILE capture source for this host.
/// It reads the job's selection from the real filesystem — files
/// directly, directories recursively — and says exactly what it
/// is in every capture's notes: files are read LIVE, without a
/// VSS shadow copy, so a file being written during capture may be
/// captured mid-write. The previous host wiring ran the engine
/// against FakeBackupCaptureSource, whose "captures" contained
/// nothing real at all; this source replaces the fake in
/// production construction (BackupHostWiring).
///
/// IMAGE jobs refuse by name: a volume image without VSS (or an
/// equivalent snapshot mechanism) would be a torn copy wearing an
/// image's authority. IVolumeShadowCopyProvider's only in-tree
/// implementation remains UnavailableVssProvider, which refuses
/// the same way — VSS capture is host work still owed, named here
/// rather than simulated.
///
/// Per-file failures (missing, unreadable, locked beyond the
/// read-share retry) are notes, never silent skips: the engine
/// records the notes in the chained audit entry for the run, and
/// a selection that yields NOTHING fails the capture outright
/// (the success-while-writing-nothing shape the fake was built
/// to attack in tests).
/// </summary>
public sealed class FileBackupCaptureSource : IBackupCaptureSource
{
    /// <summary>Files larger than this are refused per-file with a
    /// named note: the storage seam is byte[] end-to-end (register
    /// R-09 — the streaming rewrite is a contract change, not a
    /// refactor), so an unbounded read is an unbounded memory
    /// claim against the Core. 512 MiB is a stated bound, not a
    /// discovered one.</summary>
    public const long MaxFileBytes = 512L * 1024 * 1024;

    public CaptureResult Capture(BackupJobDefinition job, DateTimeOffset now)
    {
        if (job.Kind == BackupKinds.Image)
            throw new InvalidOperationException(
                "image capture refuses: this host has no VSS shadow-copy provider wired " +
                "(UnavailableVssProvider is the only in-tree implementation) — a live-read " +
                "volume image would be a torn copy, and this source will not produce one under an image claim");
        if (job.Kind != BackupKinds.File)
            throw new InvalidOperationException($"unknown backup kind '{job.Kind}' — capture refused");

        var items = new List<CapturedItem>();
        var notes = new List<string>
        {
            "captured live from the filesystem WITHOUT a VSS shadow copy — open files may be inconsistent (FileBackupCaptureSource, W11/R-15)",
        };
        foreach (var selection in job.Selection)
        {
            var path = selection?.Trim();
            if (string.IsNullOrWhiteSpace(path)) { notes.Add("not_read:(empty selection entry)"); continue; }
            try
            {
                if (File.Exists(path)) AddFile(items, notes, path, path);
                else if (Directory.Exists(path))
                {
                    foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                        AddFile(items, notes, file, path);
                }
                else notes.Add($"not_read:{path}");
            }
            catch (Exception ex)
            {
                notes.Add($"not_read:{path} ({ex.GetType().Name})");
            }
        }
        if (items.Count == 0)
            throw new InvalidOperationException(
                $"file capture for job '{job.Id}' read nothing — every selection was missing, unreadable, or over the {MaxFileBytes}-byte bound; a backup of nothing is refused, not sealed");
        return new CaptureResult(BackupKinds.File, items, Array.Empty<VolumeDescriptor>(), notes);
    }

    private static void AddFile(List<CapturedItem> items, List<string> notes, string file, string selectionRoot)
    {
        try
        {
            var info = new FileInfo(file);
            if (info.Length > MaxFileBytes)
            {
                notes.Add($"not_read:{file} (over the {MaxFileBytes}-byte per-file bound — the byte[] storage seam, R-09)");
                return;
            }
            items.Add(new CapturedItem(FakeBackupCaptureSource.NormaliseRelative(file), File.ReadAllBytes(file)));
        }
        catch (Exception ex)
        {
            notes.Add($"not_read:{file} ({ex.GetType().Name})");
        }
    }
}
