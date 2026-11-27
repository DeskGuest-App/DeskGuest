namespace DeskGuest.Shared.Ipc;

/// <summary>The Agent's trust posture for one connection attempt
/// (BD-WIN-AGENT F4).</summary>
public enum IpcTrustPosture
{
    /// <summary>A token exists: run the mutual-auth handshake; the
    /// Core is authenticated only when its HelloAck verifies.</summary>
    Authenticated,

    /// <summary>No token AND no explicit dev opt-in: FAIL CLOSED.
    /// The agent must not mark the Core authenticated, must not
    /// execute tool requests, and must refuse vault/gate/host sends.
    /// This is the posture for every launch the Core did not make
    /// (installer logon task, manual start, --portable on a machine
    /// whose Core never provisioned a token).</summary>
    RefuseNoToken,

    /// <summary>No token, but the operator explicitly set the dev
    /// opt-in for THIS process. Unauthenticated interop is allowed
    /// and must be labelled as such wherever it surfaces.</summary>
    DevUnauthenticated,
}

/// <summary>
/// BD-WIN-AGENT F4: the fail-closed trust decision for the Agent ↔
/// Core handshake. Before this, a missing token silently marked the
/// Core authenticated ("dev/test posture"), so any pipe squatter —
/// or any launch path that never received the env-only token —
/// received vault passwords, gate approvals and STOP traffic with no
/// HMAC proof at all. The decision is pure so the test project can
/// pin it; the Session Agent acts on it.
/// </summary>
public static class IpcTrust
{
    /// <summary>The explicit, per-process dev opt-in environment
    /// variable. Only the exact value "1" opts in. W19 / DS-B-17:
    /// this variable is EXCLUSIVELY the IPC posture's — it no
    /// longer enables the Core's dev-ephemeral update key (that
    /// posture has its own switch, DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY
    /// / CoreOptions.AllowDevEphemeralUpdateKey, decided by
    /// DevEphemeralUpdateKeyOptIn in DeskGuest.Core), and it is never
    /// propagated to a child Agent process.</summary>
    public const string DevOptInVariable = "DESKGUEST_DEV_ALLOW_NO_TOKEN";

    public static IpcTrustPosture Decide(string? token, string? devOptInValue)
    {
        if (!string.IsNullOrWhiteSpace(token)) return IpcTrustPosture.Authenticated;
        return string.Equals(devOptInValue?.Trim(), "1", StringComparison.Ordinal)
            ? IpcTrustPosture.DevUnauthenticated
            : IpcTrustPosture.RefuseNoToken;
    }

    /// <summary>The environment variable that names the Core's
    /// exact image path to a Core-launched Agent (W22).
    /// W25 (round-5, FIX-INADEQUATE): this variable is
    /// read from the AGENT's own environment, which its LAUNCHER
    /// controls — and a fake Core is itself a launcher, so the
    /// pre-W25 rule "a valid override wins" let the attacker choose
    /// the expected path the check then passed against. The
    /// override therefore NO LONGER ESTABLISHES trust: it may only
    /// SELECT among the install-established expected paths (the
    /// co-located set below). An override naming anything outside
    /// that set establishes NOTHING (empty result, fail closed) —
    /// a value supplied by the process that launched the Agent can
    /// never widen the trust set. The Core's launcher still sets it
    /// (strip-then-set in BuildChildEnvironment) as a selection
    /// hint among equals; the identity PROOF is the Ed25519
    /// signature against the install pin (CoreIdentity), not this
    /// path check.</summary>
    public const string CoreExeEnvironmentVariable = "DESKGUEST_CORE_EXE";

    public const string CoreExeFileName = "DeskGuestCore.exe";
    public const string AltCoreExeFileName = "DeskGuest.Core.exe";

    /// <summary>W28 SUPERSESSION: this co-located expected-path
    /// set is the LEGACY (W25) surface. The round-6 break showed
    /// any anchor derived from the Agent's own image path follows
    /// the attacker when the Agent image is copied, so the Agent
    /// handshake no longer consults this function — it uses the
    /// protected install trust record (InstallTrust:
    /// ExpectedCoreImagePaths(record, …) / IsCoreServerImage(…,
    /// record, …)). This function remains only where older tests
    /// pin the legacy behaviour; do not wire it back into a trust
    /// decision.
    ///
    /// The expected Core image path(s) for this Agent,
    /// established by its INSTALL relationship only — the same
    /// full-path binding W10 applied to the credential-provider
    /// host (CpPipeTrust). The one source is the Agent's own
    /// directory: the product's install layout (installer + update
    /// slots alike) co-locates DeskGuestCore.exe with
    /// DeskGuest.SessionAgent.exe, so the Core that belongs with this
    /// Agent is the one beside it.
    /// W25: the DESKGUEST_CORE_EXE override may only SELECT from that
    /// co-located set (it narrows the two candidate names to the
    /// one the Core's launcher named). An override naming any
    /// other path — however well-formed — establishes NOTHING
    /// (empty result, fail closed): the pre-W25 "valid override
    /// wins" rule was the round-5 break, because the override is
    /// supplied by whoever launched the Agent. A split layout
    /// (Core and Agent in sibling directories) is therefore no
    /// longer a trusted shape on this check alone; the sanctioned
    /// shapes are co-location, or the install-record pin doing the
    /// identity work with the path check as a second factor.
    /// An empty result means the expected path cannot be
    /// established, and IsCoreServerImage then refuses EVERY image
    /// — fail closed, by design.</summary>
    public static IReadOnlyList<string> ExpectedCoreImagePaths(string? agentImagePath, string? coreExeOverride)
    {
        if (string.IsNullOrWhiteSpace(agentImagePath) || !WindowsPath.IsFullyQualified(agentImagePath))
            return Array.Empty<string>();
        var normalized = WindowsPath.Normalize(agentImagePath);
        var sep = normalized.LastIndexOf('\\');
        if (sep < 0) return Array.Empty<string>();
        var dir = normalized[..sep];
        var colocated = new[] { dir + "\\" + CoreExeFileName, dir + "\\" + AltCoreExeFileName };
        if (!string.IsNullOrWhiteSpace(coreExeOverride))
        {
            var selected = colocated.FirstOrDefault(
                e => WindowsPath.EqualsFull(coreExeOverride, e));
            return selected is not null ? new[] { selected } : Array.Empty<string>();
        }
        return colocated;
    }

    /// <summary>Image the Agent accepts as its Core when verifying
    /// the pipe server process (GetNamedPipeServerProcessId + image
    /// query). Anything else hosting the pipe name is a squatter,
    /// however good its HMAC game is.
    /// W22 (round-4): the pre-fix decision accepted ANY
    /// fully-qualified path NAMED DeskGuestCore.exe/DeskGuest.Core.exe — a
    /// token reader could run a fake Core from any user-writable
    /// directory and be treated as the authenticated Core for
    /// vault/gate/STOP traffic. The decision now binds the FULL
    /// expected path (ExpectedCoreImagePaths): the observed image
    /// must EQUAL the Core path established from the Agent's
    /// launch/install relationship, under WindowsPath semantics.
    /// No establishable expected path ⇒ no image passes.</summary>
    public static bool IsCoreServerImage(string? imagePath, string? agentImagePath, string? coreExeOverride = null)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return false;
        if (!WindowsPath.IsFullyQualified(imagePath)) return false;
        var expected = ExpectedCoreImagePaths(agentImagePath, coreExeOverride);
        if (expected.Count == 0) return false;
        return expected.Any(e => WindowsPath.EqualsFull(imagePath, e));
    }
}
