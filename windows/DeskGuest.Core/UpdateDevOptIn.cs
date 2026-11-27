namespace DeskGuest.Core;

/// <summary>
/// W19 / DS-B-17: the ONE canonical decision for the dev-ephemeral
/// UPDATE-key posture. Before the split, CoreRuntime read
/// DESKGUEST_DEV_ALLOW_NO_TOKEN — the IPC no-token opt-in
/// (DeskGuest.Shared.Ipc.IpcTrust.DevOptInVariable) — to decide whether
/// an absent pinned update key fell back to a fresh in-process
/// "dev-ephemeral" keypair. One variable drove two orthogonal
/// trust decisions: package authenticity (host-level, update
/// trust root) and local peer authentication (per-process IPC).
/// It could not express "ephemeral update key but authenticated
/// IPC" or the reverse, and cell (a) of the review's independence
/// matrix failed: setting the IPC var alone silently un-pinned
/// the update trust root.
///
/// The split (round-3 (iii), verbatim in substance):
///   * the update posture is decided HERE, and only here — by
///     CoreOptions.AllowDevEphemeralUpdateKey (code opt-in) or the
///     dedicated environment variable
///     DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1;
///   * DESKGUEST_DEV_ALLOW_NO_TOKEN is exclusively IpcTrust's (IPC);
///     nothing in the update composition references it;
///   * neither variable propagates to the child Agent (see
///     WindowsAgentLauncher.BuildChildEnvironment, which strips
///     both from the launch environment);
///   * the postures are labelled and audited separately: the
///     update posture is audit-chained by CoreRuntime as
///     "update_signing_posture"; the IPC posture is labelled by
///     the Agent itself ("DEV-UNAUTHENTICATED" in its Hello, a
///     named refusal when RefuseNoToken). Neither label borrows
///     the other's variable name.
/// </summary>
public static class DevEphemeralUpdateKeyOptIn
{
    /// <summary>The dedicated update-key dev opt-in environment
    /// variable. Only the exact value "1" opts in. This is NOT
    /// the IPC variable; setting DESKGUEST_DEV_ALLOW_NO_TOKEN has no
    /// effect here, and setting this has no effect on IpcTrust.</summary>
    public const string Variable = "DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY";

    /// <summary>The canonical decision, pure over its inputs so
    /// the independence matrix can pin every cell.</summary>
    public static bool IsInForce(bool codeOptIn, string? envValue)
        => codeOptIn || string.Equals(envValue?.Trim(), "1", StringComparison.Ordinal);

    /// <summary>The production read: code opt-in from the composed
    /// options, env value from this process's environment.</summary>
    public static bool IsInForce(CoreOptions options)
        => IsInForce(options.AllowDevEphemeralUpdateKey, Environment.GetEnvironmentVariable(Variable));
}
