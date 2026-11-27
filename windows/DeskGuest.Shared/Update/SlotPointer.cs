using System.Text.Json;

namespace DeskGuest.Shared.Update;

/// <summary>Which A/B slot the update pointer names. Serialized as a
/// number in active-slot.json (0 = A, 1 = B) — the on-disk format is
/// owned by DeskGuest.Core's UpdateManager; this reader is its tolerant
/// mirror for the launcher shim.</summary>
public enum SlotId { A = 0, B = 1 }

/// <summary>
/// The active-slot pointer (DESIGN §4.6), read tolerantly: a missing
/// or corrupt pointer defaults to slot A — the launcher must ALWAYS
/// be able to start something, and slot A is the install-time slot.
/// The reader never throws.
/// </summary>
public sealed record SlotPointer(SlotId Active, string Version, string? StagedVersion, string? LastOutcome,
    // BD-WIN-AGENT F6: content hash of the ACTIVE slot, recorded by
    // the Core from the signature-verified package (see
    // SlotIntegrity). The launcher refuses to exec a slot whose
    // contents do not hash to this anchor. Null on pointers written
    // before the anchor existed (install-time slot) — the launcher
    // treats a null anchor as UNVERIFIED and falls back to base.
    string? ActiveSlotHash = null)
{
    public static SlotPointer Default => new(SlotId.A, "0.1.0", null, null);

    public static string PointerPath(string updatesRoot) => Path.Combine(updatesRoot, "active-slot.json");
    public static string SlotDir(string updatesRoot, SlotId slot) => Path.Combine(updatesRoot, "slots", slot.ToString());

    private sealed record PointerJson(int? Active, string? Version, string? StagedVersion, string? LastOutcome, string? ActiveSlotHash = null);

    public static SlotPointer Read(string updatesRoot) => ReadDetailed(updatesRoot).Pointer;

    /// <summary>The last-known-good backup the Core's UpdateManager
    /// writes beside the main pointer (W12 / DS-P9-F11).</summary>
    public static string PointerBackupPath(string updatesRoot) => PointerPath(updatesRoot) + ".bak";

    /// <summary>BD-SHARED-PLAT-3/F12: the fallback is NAMED, never
    /// silent. ReadDetailed reports WHY the pointer fell back
    /// (missing / corrupt / unknown slot value) so the launcher can
    /// log and surface it — the old shape silently started slot A
    /// at a hard-coded "0.1.0" after a bad update corrupted the
    /// pointer, with no diagnostic anywhere. A null FellBack means
    /// the pointer was read as written.</summary>
    public static SlotPointerRead ReadDetailed(string updatesRoot)
    {
        // W12 / DS-P9-F11: a missing/corrupt main pointer falls back
        // to the last-known-good .bak the Core writes — never
        // straight to the install-time slot A while a good backup
        // names the real active slot. W12 / DS-P9-F8: "{}" (missing
        // Active/Version) is corruption, not slot A.
        var main = TryRead(PointerPath(updatesRoot), out var mainReason, out var mainBytes);
        if (main is not null) return new SlotPointerRead(main, null, PointerPath(updatesRoot), mainBytes);
        var bak = TryRead(PointerBackupPath(updatesRoot), out var bakReason, out var bakBytes);
        if (bak is not null)
            return new SlotPointerRead(bak, $"main pointer unusable ({mainReason}); fell back to the last-known-good .bak", PointerBackupPath(updatesRoot), bakBytes);
        return new SlotPointerRead(Default,
            $"missing/corrupt: main pointer unusable ({mainReason}); backup unusable ({bakReason}) — install-time default (slot A)");
    }

    private static SlotPointer? TryRead(string path, out string reason) => TryRead(path, out reason, out _);

    private static SlotPointer? TryRead(string path, out string reason, out byte[]? bytes)
    {
        reason = ""; bytes = null;
        try
        {
            if (!File.Exists(path)) { reason = "missing"; return null; }
            // W19 / DS-B-16 (a): ONE read. The bytes parsed here are
            // the bytes carried on the read result, so a verifier
            // downstream hashes exactly the pointer this reader
            // consumed — never a second read of a file that may
            // have been swapped in between.
            bytes = File.ReadAllBytes(path);
            var dto = JsonSerializer.Deserialize<PointerJson>(System.Text.Encoding.UTF8.GetString(bytes));
            if (dto is null) { reason = "parsed to nothing"; return null; }
            if (dto.Active is not (0 or 1)) { reason = dto.Active is null ? "missing slot value" : $"unknown slot value {dto.Active}"; return null; }
            if (string.IsNullOrWhiteSpace(dto.Version)) { reason = "missing version"; return null; }
            var slot = dto.Active == 1 ? SlotId.B : SlotId.A;
            return new SlotPointer(slot, dto.Version, dto.StagedVersion, dto.LastOutcome, dto.ActiveSlotHash);
        }
        catch (Exception ex) { reason = $"unreadable ({ex.GetType().Name})"; return null; }
    }
}

/// <summary>The result of a pointer read: the pointer to use, plus
/// the fallback reason when the on-disk pointer could not be taken
/// as written (BD-SHARED-PLAT-3/F12). W17 / DS-B-16:
/// <paramref name="SelectedPath"/> names the file the returned
/// pointer was actually read from (main or .bak; null when the
/// install-time default was used) — a verifier must hash THAT
/// file, not "main if it exists": the pre-fix anchor hashed the
/// main file even when this reader had fallen back to the backup,
/// so a legitimate crash recovery (corrupt main, good backup)
/// was refused and the selected file was never the checked one.</summary>
public sealed record SlotPointerRead(SlotPointer Pointer, string? FellBack, string? SelectedPath = null,
    // W19 / DS-B-16 (a): the exact bytes of the selected file, from
    // the SINGLE read that produced Pointer. A verifier hashes
    // THESE bytes; re-reading the path would reopen the swap race
    // named in review (validate P0, execute the slot Pm names).
    byte[]? SelectedBytes = null);
