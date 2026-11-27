namespace DeskGuest.Shared.Ipc;

/// <summary>Where the Agent's copy of the per-boot IPC token came
/// from (W20 token channel). The label is carried in the Hello
/// payload and written to the Core's audit log — never the token.</summary>
public enum IpcTokenSource
{
    None,
    /// <summary>DESKGUEST_IPC_TOKEN in the launch environment — the
    /// Core-launched path (WindowsAgentLauncher), unchanged.</summary>
    Environment,
    /// <summary>The Core-published token file in the Core data dir —
    /// the logon-task / task-launched path (W20).</summary>
    File,
}

/// <summary>One principal in the token file's ACL plan.</summary>
public sealed record IpcTokenFileAclEntry(string Sid, string Rights, bool IsSystem);

/// <summary>
/// W20: the sanctioned token channel for task-launched agents.
///
/// Why this exists (W19 diagnosis, Defect B): the per-boot IPC token
/// previously reached an agent ONLY through the Core's own launcher
/// environment block. The product's own logon-task launch path can
/// never receive an env block from a Core that starts after (or
/// independently of) the task, so a task-launched agent always
/// decided RefuseNoToken and no agent could ever authenticate under
/// the console-host + logon-task deployment shape — a deadlock,
/// because the one token-delivering relaunch path (the watchdog)
/// was gated on a session that only an authenticated agent creates.
///
/// The channel: the Core writes the SAME per-boot token it already
/// generates to &lt;dataDir&gt;/ipc-token.txt at startup, rotating
/// it every boot (fresh token, atomic replace), deleting it on
/// clean shutdown, with an ACL granting exactly SYSTEM (full
/// control — the Core's writer identity in the service shape) and
/// the console user's SID (read + delete — the agent runs as that
/// user; delete is what lets a console-host Core, which runs AS
/// the console user, rotate and clean up its own file — a Read-only
/// grant locked the writer out of its own rotation, proven live in
/// the W20 deploy. Delete does not widen the threat: replacing the
/// file's contents still requires defeating the Core's in-memory
/// comparison, and a forged token simply fails Auth).
/// No other principal can read it: a local process running as a
/// DIFFERENT user gets an unreadable file, which the agent treats
/// exactly like an absent file (RefuseNoToken stands).
///
/// What the file token is worth: exactly what the env token is
/// worth — it IS the same secret, not a second credential. It is
/// one factor of the existing set and replaces none of them: the
/// Core still verifies the connected client's OS identity (active
/// console session + console user + expected agent image) before
/// reading a single message, and the mutual HMAC handshake is
/// unchanged. A process that somehow read the file but is not the
/// console user's agent image still fails the Core-side identity
/// check; a process that IS the console user's agent already runs
/// as the user the whole IPC design trusts at the endpoint.
///
/// This class is the pure, testable core: ACL plan construction,
/// source resolution, and atomic file mechanics. The Windows ACL
/// application itself lives in DeskGuest.Core (IpcTokenFileChannel),
/// built from the plan pinned here.
///
/// W22 hardening (round-4, verified firsthand by the
/// confirming lane): the channel's INVARIANT is that no secret
/// bytes ever rest under a non-plan ACL — not in the target file,
/// not in the temp file, not on any failure path. Publish resolves
/// the ACL plan FIRST (no plan ⇒ nothing is written, refused by
/// name), creates the temp file EMPTY, applies the plan ACL to the
/// temp file, and only then lets secret bytes land
/// (WriteAtomicProtected). Every failure path deletes.
///
/// Fast user switching — honest posture (W22 disposition of the
/// round-4 note): the plan binds ReadAndDelete to the console SID
/// resolved AT PUBLISH TIME. If the console user changes without a
/// Core restart (fast user switching), the previous console user's
/// SID keeps ReadAndDelete on the current boot's token file until
/// the next boot, when rotation re-publishes under the then-current
/// console SID. That is the bound: one boot. The new console user
/// cannot read the file in the meantime (their agent stays
/// RefuseNoToken until the next boot or a Core restart re-publishes)
/// — a liveness limit, stated plainly, not hidden. Re-publishing on
/// console-session change is the tightening this posture names as
/// future work; it is NOT implemented here and must not be claimed.
///
/// tokenSource discipline (W22 pin): the source label is
/// agent-asserted AUDIT METADATA ONLY. Posture is decided by token
/// PRESENCE (Resolve below never receives a label), the Core's
/// audit coerces any asserted label through AuditLabel before
/// recording it, and no gate, trust decision, or authorisation may
/// ever consult the label. A test pins all three properties.
/// </summary>
public static class IpcTokenFile
{
    public const string FileName = "ipc-token.txt";
    public const string TokenEnvironmentVariable = "DESKGUEST_IPC_TOKEN";
    public const string FileEnvironmentVariable = "DESKGUEST_IPC_TOKEN_FILE";
    public const string SystemSid = "S-1-5-18";

    public static string DefaultPath(string dataDir) => Path.Combine(dataDir, FileName);

    /// <summary>The ACL plan for the token file: SYSTEM full
    /// control + the console user read-only, inheritance broken so
    /// no parent-directory ACE can widen the readership. Refuses
    /// (null) when no console user is known or the "console user"
    /// is SYSTEM itself — in both cases there is no second reader
    /// to grant, and writing a SYSTEM-only file the agent can never
    /// read would be a silent no-op channel; the Core audits the
    /// refusal by name instead.</summary>
    public static IReadOnlyList<IpcTokenFileAclEntry>? BuildAclPlan(string? consoleUserSid)
    {
        if (string.IsNullOrWhiteSpace(consoleUserSid)) return null;
        var sid = consoleUserSid.Trim();
        if (string.Equals(sid, SystemSid, StringComparison.OrdinalIgnoreCase)) return null;
        return new[]
        {
            new IpcTokenFileAclEntry(SystemSid, "FullControl", IsSystem: true),
            new IpcTokenFileAclEntry(sid, "ReadAndDelete", IsSystem: false),
        };
    }

    /// <summary>Resolve the agent's token + posture from both
    /// channels. The env token wins when both exist (the launcher
    /// path is the more tightly bound delivery: it reaches exactly
    /// one process). A file token is worth the same Authenticated
    /// posture. No token from either channel falls through to the
    /// existing dev-opt-in / fail-closed decision, untouched.</summary>
    public static (IpcTrustPosture Posture, IpcTokenSource Source) Resolve(
        string? envToken, string? fileToken, string? devOptInValue)
    {
        if (!string.IsNullOrWhiteSpace(envToken))
            return (IpcTrustPosture.Authenticated, IpcTokenSource.Environment);
        if (!string.IsNullOrWhiteSpace(fileToken))
            return (IpcTrustPosture.Authenticated, IpcTokenSource.File);
        return (IpcTrust.Decide(null, devOptInValue), IpcTokenSource.None);
    }

    /// <summary>FR-119 (W76): bounded orphan handling for the
    /// token resolution above. An agent launched by a Core carries
    /// that boot's token in its environment; when the Core restarts
    /// it ROTATES the token and republishes the new one to the
    /// token file — so an orphaned agent that keeps presenting its
    /// stale ENV token can never authenticate again, yet the old
    /// resolution retried it forever (env always wins), holding a
    /// tray icon and spamming retries while the watchdog's fresh
    /// agent did the real recovery (W69 live record).
    ///
    /// This policy is the bounded answer, pure so the harness pins
    /// it: only AUTH failures count (a handshake that presented a
    /// token and was refused / failed mutual auth). A connect
    /// failure — Core down or restarting — is never recorded here,
    /// so the agent still never dies because a Core is restarting.
    /// After <see cref="EnvAuthFailureLimit"/> consecutive auth
    /// failures on the env token, resolution falls back to the
    /// FILE token (the current boot's published secret — the same
    /// secret by the other sanctioned delivery). If there is no
    /// usable distinct file token, or the file token also fails
    /// <see cref="FileAuthFailureLimit"/> auth attempts, the agent
    /// is an orphan with no recovery path of its own and
    /// <see cref="ShouldExit"/> latches: the host exits the process
    /// cleanly and the Core's watchdog relaunches a fresh agent
    /// with a current token — the recovery path that already works.
    /// Any success resets the accounting entirely.</summary>
    public sealed class TokenRetryPolicy
    {
        public const int EnvAuthFailureLimit = 3;
        public const int FileAuthFailureLimit = 3;

        private int _envAuthFailures;
        private int _fileAuthFailures;
        private bool _envRejected;

        /// <summary>Latched once the env token has failed auth the
        /// bounded number of times: env no longer wins.</summary>
        public bool EnvRejected => _envRejected;

        /// <summary>True when every sanctioned token this process
        /// can present has been refused the bounded number of times
        /// (or the env token was refused and no distinct file token
        /// exists): exit cleanly and let the watchdog relaunch.</summary>
        public bool ShouldExit { get; private set; }

        /// <summary>Resolve the token to present on the next
        /// attempt. Before the env token is rejected this is exactly
        /// <see cref="Resolve(string?, string?, string?)"/> (env
        /// wins). After rejection, a distinct file token wins; an
        /// absent or identical file token offers nothing new, so
        /// the attempt resolves to no token (the caller then counts
        /// the exhaustion via <see cref="RecordAuthFailure"/>).</summary>
        public (string? Token, IpcTokenSource Source) Current(string? envToken, string? fileToken)
        {
            if (!_envRejected)
            {
                var (_, source) = Resolve(envToken, fileToken, null);
                return source switch
                {
                    IpcTokenSource.Environment => (envToken!.Trim(), source),
                    IpcTokenSource.File => (fileToken, source),
                    _ => (null, IpcTokenSource.None),
                };
            }
            if (!string.IsNullOrWhiteSpace(fileToken)
                && !string.Equals(fileToken.Trim(), envToken?.Trim(), StringComparison.Ordinal))
                return (fileToken, IpcTokenSource.File);
            return (null, IpcTokenSource.None);
        }

        /// <summary>Record one AUTH failure for the source that was
        /// presented (never call for connect failures). Latches the
        /// env rejection at the limit, and latches
        /// <see cref="ShouldExit"/> when the fallback is exhausted:
        /// the file source failed its limit, or a failure arrives
        /// with no token left to present (env rejected and no
        /// distinct file token exists).</summary>
        public void RecordAuthFailure(IpcTokenSource presented)
        {
            switch (presented)
            {
                case IpcTokenSource.Environment:
                    _envAuthFailures++;
                    if (_envAuthFailures >= EnvAuthFailureLimit) _envRejected = true;
                    break;
                case IpcTokenSource.File:
                    _fileAuthFailures++;
                    if (_fileAuthFailures >= FileAuthFailureLimit) ShouldExit = true;
                    break;
                default:
                    // Nothing was presented and auth still failed
                    // after the env token was rejected: no recovery
                    // path remains in this process.
                    if (_envRejected) ShouldExit = true;
                    break;
            }
            // Env rejected + no file attempts possible is decided by
            // the None case above / the caller's next Current().
        }

        /// <summary>A successful authentication clears all failure
        /// accounting — the fallback was a recovery, not a stain.</summary>
        public void RecordSuccess()
        {
            _envAuthFailures = 0;
            _fileAuthFailures = 0;
            _envRejected = false;
            ShouldExit = false;
        }
    }

    /// <summary>The audit label for a source (metadata only).</summary>
    public static string SourceLabel(IpcTokenSource source) => source switch
    {
        IpcTokenSource.Environment => "env",
        IpcTokenSource.File => "file",
        _ => "none",
    };

    /// <summary>W22: coerce an AGENT-ASSERTED source label (it
    /// arrives inside the Hello payload, so any string can be put
    /// there) to the canonical audit vocabulary before it is
    /// recorded. A label outside {env, file, none} records as
    /// "unrecognized" — a forged label can neither inject text into
    /// the audit chain nor impersonate a delivery channel. This is
    /// an audit-hygiene function ONLY: nothing branches on its
    /// result except the audit string itself (see the tokenSource
    /// discipline note on the class).</summary>
    public static string AuditLabel(string? asserted) => asserted?.Trim() switch
    {
        "env" => "env",
        "file" => "file",
        "none" => "none",
        _ => "unrecognized",
    };

    /// <summary>Read a token file. ANY failure — absent, unreadable
    /// (wrong-user ACL), malformed — returns null, which the
    /// resolver treats as no token: RefuseNoToken stands. A token
    /// is the Core's format: 64 hex chars (32 random bytes).</summary>
    public static string? Read(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var text = File.ReadAllText(path).Trim();
            return IsWellFormed(text) ? text : null;
        }
        catch { return null; }
    }

    public static bool IsWellFormed(string? token) =>
        token is { Length: 64 } && token.All(Uri.IsHexDigit);

    /// <summary>Atomic publish: write a sibling temp file, then
    /// replace in one move — a reader never sees a torn token, and
    /// rotation never leaves a window where the file holds the old
    /// boot's secret alongside the new one's name. NOTE (W22): this
    /// plain form writes the secret into the temp file BEFORE any
    /// ACL exists on it; the token channel must use
    /// WriteAtomicProtected instead. This form remains for callers
    /// whose content is not a secret under an ACL plan.</summary>
    public static void WriteAtomic(string path, string token)
    {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(tmp, token);
        try { File.Move(tmp, path, overwrite: true); }
        catch { try { File.Delete(tmp); } catch { } throw; }
    }

    /// <summary>W22: ACL-first atomic publish — the token channel's
    /// only write path. Order is the whole fix:
    /// 1) the temp file is created EMPTY (no secret bytes exist
    ///    anywhere yet);
    /// 2) <paramref name="protectTempFile"/> applies the ACL plan
    ///    to the temp file (the Core's ApplyAcl; null on hosts with
    ///    no ACL to apply, where the caller has already named that
    ///    posture in its status string);
    /// 3) only then do the secret bytes land, into a file already
    ///    carrying the plan ACL;
    /// 4) the move replaces the target with the protected temp
    ///    file — the target therefore carries the plan ACL from the
    ///    first instant it holds the new secret.
    /// ANY failure deletes the temp file before rethrowing, so no
    /// failure path leaves secret bytes (or a stray temp) behind:
    /// if the failure precedes step 3 no secret was ever written;
    /// if it follows, the only copy is deleted with the temp.</summary>
    public static void WriteAtomicProtected(string path, string token, Action<string>? protectTempFile,
        Action<string>? afterSecretWritten = null)
    {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllText(tmp, string.Empty);
            protectTempFile?.Invoke(tmp);
            File.WriteAllText(tmp, token);
            // W25 (item 5): the caller's chance to RE-APPLY the
            // strict plan ACL to the temp now that the secret has
            // landed — the console-host writer needed a self-write
            // grant to perform the write above (see
            // IpcTokenFileChannel), and that grant must not survive
            // into the moved target. Runs before the move; a throw
            // here deletes the temp like every other failure.
            afterSecretWritten?.Invoke(tmp);
            File.Move(tmp, path, overwrite: true);
        }
        catch { try { File.Delete(tmp); } catch { } throw; }
    }

    /// <summary>Clean-shutdown removal. Best-effort by design: a
    /// leftover file holds a dead boot's token, which the next
    /// boot's rotation replaces before any agent can use it.</summary>
    public static void Delete(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
