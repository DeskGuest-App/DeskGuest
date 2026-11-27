using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.Update;

/// <summary>
/// BD-WIN-AGENT F6: the slot-integrity anchor shared by the Core
/// (which records the hash when it stages a signature-verified
/// package) and the Launcher (which re-verifies the active slot
/// before it execs anything from it). ONE implementation, so the
/// hash recorded at stage time and the hash checked at exec time
/// can never drift apart.
///
/// The chain of trust: the update package is RSA-verified against
/// the pinned product key BEFORE extraction (UpdateManager); the
/// Core records this content hash of the extracted slot in the
/// pointer at stage time, re-verifies it at apply time, and carries
/// it into the flipped pointer as the ACTIVE slot hash; the
/// launcher recomputes it at every service start and falls back to
/// the install-root base binaries on any mismatch — a binary simply
/// dropped into the slot directory (the pre-fix behaviour: existence
/// was the only test) is never executed.
///
/// Named residual: the pointer file itself lives in the updates
/// root, so an attacker who can rewrite BOTH the slot and the
/// pointer defeats the hash alone. Closing that leg needs an
/// Authenticode/signed-manifest check or installer ACL hardening of
/// the updates root — neither exists in this payload (no release
/// key, no installer), so it is recorded as a remainder, not
/// claimed.
///
/// W13 / DS-P9-F18 (the verify→exec TOCTOU limb, CLOSED for file
/// replacement): the launcher no longer verifies once and execs
/// whenever. LauncherCore.RunAsync re-resolves (and re-verifies)
/// immediately before starting the child, and the production
/// starter holds every verified slot file open with write-sharing
/// DENIED for the child's lifetime — a hashed file cannot be
/// replaced between verification and exec, or while it runs; a
/// file that cannot be held refuses the start.
///
/// W15 / DS-P9-F18 limb (a) — CLOSED: verification now covers the
/// WHOLE slot directory at exec time. The production starter
/// acquires a <see cref="SlotHold"/>: the content hash is verified,
/// EVERY file present is snapshotted and held deny-write, and
/// immediately before the child starts the hold re-snapshots and
/// re-hashes — a file ADDED between verify and exec (or while the
/// hold is being taken) is named and refuses the start, as is a
/// removed or changed file.
///
/// W15 / DS-P9-F18 limb (b) — pointer rewrite: closed as far as is
/// sound WITHOUT a production signing key, via the audit-chained
/// pointer record (see PointerAuditAnchor): a pointer rewritten
/// together with the slot no longer matches the hash the Core
/// recorded in the enterprise audit chain, and the launcher
/// refuses the slot by name. The remainder is named there and
/// stands: full closure needs the production signing key (signed
/// pointer / Authenticode) — a human item; no key exists and no
/// signature is faked.
///
/// W17 / DS-B-15 — the CheckIntact→Process.Start DIRECTORY-swap
/// race (the W15 remainder above): closed on Windows by holding
/// the slot directory itself (and its first two ancestors)
/// deny-rename/delete for the child's lifetime — see SlotHold.
/// W17 / DS-B-16 — the audit-anchor downgrade-by-deletion and the
/// main-vs-backup selection rule: closed in PointerAuditAnchor
/// via anchor-presence markers + the reader's SelectedPath; the
/// tamper-evidence limit is restated there, not overstated.
/// </summary>
public static class SlotIntegrity
{
    /// <summary>Deterministic hash over a slot directory's contents
    /// (relative path + length + per-file SHA-256, ordinal-sorted).
    /// Throws on IO failure — callers fail closed.</summary>
    public static string ContentHash(string dir)
    {
        using var sha = SHA256.Create();
        // W12 / DS-P9-F18: reparse points are refused — a junction or
        // symlink inside the slot would make the "slot contents"
        // include files outside the slot (attacker-chosen, unbounded).
        if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("slot directory is a reparse point — refused");
        var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
            .OrderBy(f => Path.GetRelativePath(dir, f), StringComparer.Ordinal).ToList();
        foreach (var f in files)
        {
            if ((File.GetAttributes(f) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"slot entry '{Path.GetRelativePath(dir, f)}' is a reparse point — refused");
        }
        foreach (var d in Directory.EnumerateDirectories(dir, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"slot directory '{Path.GetRelativePath(dir, d)}' is a reparse point — refused");
        }
        foreach (var f in files)
        {
            var rel = Path.GetRelativePath(dir, f).Replace(Path.DirectorySeparatorChar, '/');
            var head = Encoding.UTF8.GetBytes($"{rel}|{new FileInfo(f).Length}|");
            sha.TransformBlock(head, 0, head.Length, null, 0);
            var fileHash = SHA256.HashData(File.ReadAllBytes(f));
            sha.TransformBlock(fileHash, 0, fileHash.Length, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
    }

    /// <summary>True when the slot directory's current contents hash
    /// to <paramref name="expectedHash"/>; false on mismatch, missing
    /// anchor, or any IO failure (fail closed).</summary>
    public static bool Verify(string dir, string? expectedHash)
    {
        if (string.IsNullOrWhiteSpace(expectedHash)) return false;
        try
        {
            if (!Directory.Exists(dir)) return false;
            return string.Equals(ContentHash(dir), expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>The slot's file set: every file under the directory,
    /// as '/'-separated relative paths, ordinal-sorted — the same
    /// enumeration ContentHash covers. Throws on IO failure or a
    /// reparse point (callers fail closed).</summary>
    public static IReadOnlyList<string> SnapshotFiles(string dir)
    {
        if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("slot directory is a reparse point — refused");
        return Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(dir, f).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(f => f, StringComparer.Ordinal).ToList();
    }

    /// <summary>W15 / DS-P9-F18 limb (a): verify the WHOLE slot
    /// against <paramref name="expectedHash"/>, then hold EVERY file
    /// present open with write-sharing denied. Throws a named
    /// InvalidOperationException when the hash does not verify or a
    /// file cannot be held — the caller refuses the start. The
    /// returned hold's <see cref="SlotHold.CheckIntact"/> must be
    /// called immediately before exec: it re-snapshots and re-hashes,
    /// so a file added after verification refuses the start BY NAME.</summary>
    public static SlotHold AcquireHold(string dir, string expectedHash)
    {
        if (string.IsNullOrWhiteSpace(expectedHash))
            throw new InvalidOperationException("slot hold refused: no integrity anchor (expected hash) — nothing is held or executed");
        string actual;
        try { actual = ContentHash(dir); }
        catch (Exception ex) { throw new InvalidOperationException($"slot hold refused: slot contents could not be hashed ({ex.GetType().Name}: {ex.Message})", ex); }
        if (!string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"slot hold refused: slot contents hash {actual} does not match the recorded anchor {expectedHash} — nothing is held or executed");
        var files = SnapshotFiles(dir);
        var hold = new SlotHold(dir, expectedHash, files);
        try
        {
            hold.OpenAll();
            // A file added while the holds were being taken is not
            // in the snapshot and holds nothing — catch it NOW, at
            // acquisition, not only at the pre-exec check.
            if (hold.CheckIntact() is { } problem)
                throw new InvalidOperationException(problem);
            return hold;
        }
        catch { hold.Dispose(); throw; }
    }
}

/// <summary>W15 / DS-P9-F18 limb (a): deny-write holds over every
/// file of a verified slot, plus the whole-directory intact check.
/// On non-Windows hosts FileShare semantics are advisory — the
/// snapshot + re-hash in <see cref="CheckIntact"/> is the portable
/// half of the guarantee and runs everywhere.
///
/// W17 / DS-B-15 — the directory-swap race, CLOSED on Windows:
/// file holds pin the FILES, but the pre-fix hold left the slot
/// DIRECTORY itself free: between CheckIntact and Process.Start
/// an attacker could rename the verified directory away and put
/// a different directory at the slot path — every held handle
/// still pointed at the verified (now renamed) files while the
/// path the starter exec'd resolved to the attacker's. On
/// Windows the hold now ALSO opens the slot directory and its
/// first two ancestors (for the production layout: slots/ and
/// the updates root) with sharing limited to READ — rename and
/// delete of a held directory are denied while any handle is
/// open without FILE_SHARE_DELETE, so the path the starter
/// resolves at exec time can only reach the held directory.
/// A directory that cannot be held refuses the start, exactly
/// like a file that cannot be held. Off Windows there is no
/// managed handle with those semantics: the portable half
/// (snapshot + re-hash in CheckIntact, re-run by the production
/// starter AFTER Process.Start with the child killed on drift)
/// is the guarantee there, and it is named as the weaker half —
/// production is the Windows service, where the handles bind.</summary>
public sealed class SlotHold : IDisposable
{
    private readonly string _dir;
    private readonly string _expectedHash;
    private readonly List<FileStream> _streams = new();
    private readonly List<IntPtr> _dirHandles = new();

    internal SlotHold(string dir, string expectedHash, IReadOnlyList<string> files)
    {
        _dir = dir;
        _expectedHash = expectedHash;
        HeldFiles = files;
    }

    /// <summary>Relative paths of every file held, ordinal-sorted.</summary>
    public IReadOnlyList<string> HeldFiles { get; }

    /// <summary>W17 / DS-B-15: directories held deny-rename/delete
    /// (slot directory + first two ancestors). Non-empty only on
    /// Windows — see the class doc for the off-Windows posture.</summary>
    public IReadOnlyList<string> HeldDirectories { get; private set; } = Array.Empty<string>();

    internal void OpenAll()
    {
        foreach (var rel in HeldFiles)
        {
            var full = Path.Combine(_dir, rel.Replace('/', Path.DirectorySeparatorChar));
            _streams.Add(new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read));
        }
        if (OperatingSystem.IsWindows())
        {
            var dirs = new List<string>();
            DirectoryInfo? cur = new DirectoryInfo(_dir);
            for (var i = 0; i < 3 && cur is not null; i++) { dirs.Add(cur.FullName); cur = cur.Parent; }
            foreach (var dir in dirs)
            {
                var handle = Native.CreateFile(dir, 0, Native.FILE_SHARE_READ, IntPtr.Zero,
                    Native.OPEN_EXISTING, Native.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                    throw new InvalidOperationException(
                        $"slot hold refused: directory '{dir}' could not be held deny-rename/delete (win32 {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}) — start refused (W17/DS-B-15)");
                _dirHandles.Add(handle);
            }
            HeldDirectories = dirs;
        }
    }

    private static class Native
    {
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
    }

    /// <summary>Null when the slot is exactly as verified: same file
    /// set, same content hash. Otherwise a named refusal describing
    /// the added file(s), the missing file(s), or the hash drift —
    /// the caller refuses the start on any non-null result.</summary>
    public string? CheckIntact()
    {
        IReadOnlyList<string> now;
        try { now = SlotIntegrity.SnapshotFiles(_dir); }
        catch (Exception ex) { return $"slot changed since verification: file set could not be re-read ({ex.GetType().Name}) — start refused"; }
        var added = now.Except(HeldFiles, StringComparer.Ordinal).ToList();
        if (added.Count > 0)
            return $"slot changed since verification: file(s) ADDED after verification are neither hashed nor held [{string.Join(", ", added)}] — start refused (DS-P9-F18 limb (a))";
        var missing = HeldFiles.Except(now, StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
            return $"slot changed since verification: verified file(s) missing [{string.Join(", ", missing)}] — start refused";
        string current;
        try { current = SlotIntegrity.ContentHash(_dir); }
        catch (Exception ex) { return $"slot changed since verification: contents could not be re-hashed ({ex.GetType().Name}) — start refused"; }
        if (!string.Equals(current, _expectedHash, StringComparison.OrdinalIgnoreCase))
            return $"slot changed since verification: content hash {current} no longer matches the recorded anchor {_expectedHash} — start refused";
        return null;
    }

    public void Dispose()
    {
        foreach (var s in _streams) s.Dispose(); _streams.Clear();
        if (OperatingSystem.IsWindows())
            foreach (var h in _dirHandles) { try { Native.CloseHandle(h); } catch { } }
        _dirHandles.Clear();
    }
}
