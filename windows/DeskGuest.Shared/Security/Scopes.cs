namespace DeskGuest.Shared.Security;

/// <summary>
/// DeskGuest scope model (SPEC §5.2 + DESIGN §6.3). Scopes are independent;
/// a pairing may hold any subset. New pairings default to Observe only.
/// `unlock` is the Windows-host scope (DESIGN §5.4) — reserved here,
/// granted by no Phase 0 flow, exercised by no Phase 0 tool.
/// </summary>
public static class Scopes
{
    public const string Observe = "observe";
    public const string Drive = "drive";
    public const string Shell = "shell";
    public const string Admin = "admin";
    public const string Unlock = "unlock";
    /// <summary>The session terminal capability (Block F, D9 leash):
    /// a NAMED capability in a pairing's scope. No preset includes
    /// it — for AIs it is OFF unless the pairing admin explicitly
    /// scopes it in.</summary>
    public const string Terminal = "terminal";
    /// <summary>RMM-10: the background-tools scope. Background rights
    /// are a SEPARATE grant from session scopes: an org can grant
    /// sessions without background rights and vice versa. No preset
    /// includes it — it is scoped in explicitly, like Terminal.</summary>
    public const string BackgroundTools = "background_tools";
    /// <summary>RMM-10 Backstage: the separately-permissioned scope
    /// for a hidden desktop session. Nothing implies it — not admin,
    /// not background_tools, not full_control. No preset includes it.</summary>
    public const string Backstage = "backstage";
    /// <summary>BD-SHARED-RMM-1 F6: admitting a SHARED toolbox kit
    /// is an administrative act over every background pairing on
    /// the device, so it carries its own scope — background_tools
    /// alone no longer suffices. Like Terminal it is in no preset
    /// and not in All: scoped in explicitly, by name.</summary>
    public const string KitAdmin = "background_kit_admin";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Observe, Drive, Shell, Admin, Unlock, BackgroundTools, Backstage };

    /// <summary>User-facing presets (SPEC §5.3). Levels tune capability only,
    /// never the consent floor.</summary>
    public static IReadOnlySet<string> Preset(string preset) => preset switch
    {
        "look_only" => new HashSet<string> { Observe },
        "full_control" => new HashSet<string> { Observe, Drive, Shell, Admin },
        _ => new HashSet<string> { Observe }
    };
}

/// <summary>Where a tool executes (DESIGN §7.1 session requirement).</summary>
public enum SessionRequirement { Core, Agent, Either }

/// <summary>Destructiveness tier (CENSUS convention).</summary>
public enum RiskTier { Low, Medium, High, Critical }
