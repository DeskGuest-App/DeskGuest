using System.Text.Json;

namespace DeskGuest.Shared.Presence;

/// <summary>The tray popup's mesh line (Block H fix). The line is
/// derived from the host-state snapshot's mesh facts — the one
/// document the Core pushes to the agent over the authenticated
/// IPC channel — never from a surface-local fetch. The pre-fix
/// popup fetched http://127.0.0.1:8741/mesh/state with a 1.5 s
/// timeout, but the Core's loopback lane is dev/tests-only
/// (CoreOptions.IncludeLoopbackLane defaults false), so in
/// production the fetch could never succeed: the popup read "state
/// unavailable" permanently while the host window, reading the
/// snapshot, showed the live state. One source, both surfaces —
/// they can no longer disagree. "State unavailable" survives only
/// for its one truthful case: no snapshot has ever arrived, which
/// means the agent has no Core contact at all.</summary>
public static class MeshLineText
{
    public const string Unavailable = "▣  This PC mesh · state unavailable";

    public static string For(string? meshState, string? phoneName) => meshState switch
    {
        "AI_DRIVING" => "▣  This PC mesh · an AI session is live",
        "HUMAN_MANUAL" => string.IsNullOrWhiteSpace(phoneName)
            ? "▣  This PC mesh · being driven from the phone"
            : $"▣  This PC mesh · being driven from {phoneName}",
        "HUMAN_SESSION" => "▣  This PC mesh · a remote session is live",
        "IDLE" => "▣  This PC mesh · Idle",
        _ => Unavailable,
    };

    /// <summary>Derive the line from a host-state snapshot JSON
    /// document (the mesh fact the Core now carries). Any parse
    /// failure or missing fact yields the unavailable line — the
    /// popup shows what it actually knows, never a guess.</summary>
    public static string FromSnapshotJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("mesh", out var mesh) ||
                mesh.ValueKind != JsonValueKind.Object)
                return Unavailable;
            var state = mesh.TryGetProperty("state", out var s) ? s.GetString() : null;
            var phone = mesh.TryGetProperty("phone", out var p) ? p.GetString() : null;
            return For(state, phone);
        }
        catch { return Unavailable; }
    }
}
