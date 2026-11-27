using System.Text.Json;

namespace DeskGuest.Shared.Ipc;

/// <summary>The DeskGuestCore service's state IN FORCE on this
/// machine (W35 amendment to W28). W28 classified the machine
/// from the mere EXISTENCE of the HKLM DeskGuestCore service key;
/// W33-B proved that wrong live: a service installed but
/// STOPPED (an old binary) while Core+Agent actually run
/// console-host made the console-provisioned record classify
/// store-untrusted and the Agent refuse everything. Shape now
/// reflects the shape in force: a service that is not running
/// is not in force. Unknown = the key exists but the running
/// state could not be read — treated as IN FORCE (fail closed:
/// an unreadable state never opens the console-host limit).</summary>
public enum InstallTrustServiceState
{
    NotInstalled,
    Stopped,
    Running,
    Unknown,
}

/// <summary>How much the Agent may trust the install trust
/// record's STORE (W28) — a property of who could have written
/// the record, never of its contents.</summary>
public enum InstallTrustPosture
{
    /// <summary>The record store is protected from the console
    /// user: owned by SYSTEM or Administrators, and no ACL entry
    /// grants any other principal a write-like right. Only the
    /// installer (elevated) or the SYSTEM Core could have written
    /// it. This is the shipped service shape's posture.</summary>
    ProtectedService,

    /// <summary>Console-host (Path B) shape: no DeskGuestCore service
    /// is RUNNING (W35: not installed, or installed but stopped),
    /// and the record was written by the console
    /// user's own Core. NAMED LIMIT, not papered over: a record
    /// the console user can write is only as trustworthy as that
    /// account — same-user impersonation is NOT excluded in this
    /// shape (the W25 console-host limit, unchanged). The record
    /// still binds against every OTHER principal.</summary>
    ConsoleHost,

    /// <summary>The store could have been written by someone who
    /// must not be able to mint trust — in the service shape, ANY
    /// record not provably protected lands here. Fail closed.</summary>
    Untrusted,
}

/// <summary>Why the Agent refused to authenticate (W28). Every
/// value names a state the Agent writes to its diagnostic /
/// audit log verbatim — a refusal is never silent.</summary>
public enum InstallTrustRefusal
{
    None,
    RecordAbsent,
    RecordMalformed,
    RecordStoreUntrusted,
    AgentNotRegistered,
    CoreOverrideOutsideRecord,
}

/// <summary>The protected install record (W28): the Core identity
/// PUBLIC key plus the registered Agent and Core image paths.
/// Written ONLY by the installer / the SYSTEM Core on first run
/// (InstallTrustRecordChannel in DeskGuest.Core); read by the Agent
/// from the fixed machine location (InstallTrust.RecordPath) —
/// never from beside the Agent's own image.</summary>
public sealed record InstallTrustRecord(byte[] CorePublicKey, string AgentImagePath, string CoreImagePath)
{
    public string CorePublicKeyBase64 => Convert.ToBase64String(CorePublicKey);
}

/// <summary>The Agent's complete trust decision for one
/// connection attempt (W28). State is the audit-vocabulary string
/// naming the outcome ("install_trust_record:ok",
/// "install_trust_record:absent", …).</summary>
public sealed record InstallTrustDecision(
    bool Accepted, InstallTrustRefusal Refusal, string State,
    InstallTrustPosture Posture, InstallTrustRecord? Record)
{
    public byte[]? PinnedCorePublicKey => Record?.CorePublicKey;
    public string? ExpectedCoreImagePath => Record?.CoreImagePath;
}

/// <summary>
/// W28: the install trust record — the fix for the round-6 FIX-INADEQUATE break on the W25 Core identity.
///
/// THE BREAK (round 6, Item 2): W25 pinned the Core's public key
/// in core-identity.pub BESIDE THE AGENT'S OWN IMAGE and derived
/// the expected Core path from the Agent's own directory — both
/// anchors follow Environment.ProcessPath, which the console user
/// controls by choosing where the Agent image runs from. The
/// user copies the (readable) Agent exe to a user-writable
/// directory, plants their own core-identity.pub + a fake
/// DeskGuestCore.exe holding the read token beside the copy, and
/// launches the copy: pin, path set and token are ALL
/// attacker-supplied, so the fake authenticates fully while the
/// real Core runs as SYSTEM. Probed firsthand by this lane
/// against the W25 decision functions before the fix: path check
/// True, HMAC True, proof against the attacker's pin True.
///
/// THE FIX: the trust anchor moves into a machine record a
/// console user cannot write.
///   * The record (this class) holds the Core identity PUBLIC
///     key and the REGISTERED Agent + Core image paths. It lives
///     at ONE fixed machine location — %ProgramData%\DeskGuest\trust\
///     agent-trust-record.json — in a directory the installer
///     ACLs to SYSTEM + Administrators (full) and console users
///     (read + execute only, NO create/write). The record file
///     itself carries BuildRecordAclPlan: SYSTEM + Administrators
///     full control, the console user READ ONLY (the Agent runs
///     as that user and must read it; read of a PUBLIC key and
///     two paths discloses nothing secret).
///   * PROVISIONING (who writes, and the fresh-install race):
///     the installer creates the protected trust directory
///     BEFORE the service first starts, so a console user cannot
///     pre-create the record or its directory. The SYSTEM Core
///     writes the record on first run (and re-asserts it every
///     boot, from its own identity key + the service-configured
///     Agent path + its own image path — never from any existing
///     record content). The Agent additionally refuses a record
///     whose store is not provably protected in the service
///     shape (owner + ACL compliance, ClassifyStore), so even a
///     record planted before the installer ran is refused, not
///     trusted. Absent or malformed record ⇒ fail closed, state
///     named in the Agent's log.
///   * The Agent reads its pin and the registered paths ONLY
///     from this record. It refuses to authenticate when its own
///     CANONICAL image path is not the registered Agent path
///     (the copied-Agent attack dies here even before the pipe
///     is considered), and accepts a Core only at the registered
///     Core path. DESKGUEST_CORE_EXE remains selection-only and can
///     never widen beyond the record (an override naming
///     anything but the registered Core path refuses).
///   * CANONICALISATION: paths are compared after resolving
///     filesystem links (symlinks / junctions, component by
///     component) and lexical dot-segment canonicalisation
///     (WindowsPath.Canonicalize). The round-6 symlink variant is
///     covered whether or not Environment.ProcessPath follows
///     links (this lane's probe: on .NET 10/Linux it resolves to
///     the target; Windows behaviour is not assumed either way).
///     A symlink launch OF the registered image canonicalises
///     back to the registered image and is genuine; a symlink to
///     a COPY canonicalises to the copy and is refused.
///
/// SUPERSESSION (migration): W25 Agents read the beside-image
/// pin; W28 Agents read ONLY the record and ignore beside-image
/// pins entirely (a beside-image core-identity.pub is now
/// diagnostic material the Core still publishes for operators,
/// never a trust input). Mixed-version consequence, as already
/// established for W25: redeploy moves Core + Agent together —
/// a W28 Agent against a pre-W28 Core finds no record (the old
/// Core never provisions one) and fails closed; a W25 Agent
/// against a W28 Core keeps its old beside-image behaviour until
/// it is replaced.
///
/// CONSOLE-HOST (Path B) PROVISIONING — the named limit applied
/// to the record: with no installer and no service, the Core
/// runs AS the console user and writes the record itself, into
/// the same fixed location, under that user's ownership. The
/// Agent detects the shape in force (W35: no DeskGuestCore service
/// RUNNING — an installed-but-stopped service is not in force,
/// and a provably protected store binds the service shape
/// regardless of service state) and
/// accepts a same-user record under ConsoleHost posture. That
/// record is only as trustworthy as the account: same-user
/// impersonation is NOT excluded in that shape, exactly the
/// W25 named limit — stated here and in the Agent's log line,
/// never papered over.
/// </summary>
public static class InstallTrust
{
    public const string RecordFileName = "agent-trust-record.json";
    public const string TrustDirName = "trust";
    public const string RecordVersion = "deskguest-install-trust:v1";

    /// <summary>The record's path under a data dir's PARENT:
    /// dataDir is %ProgramData%\DeskGuest\data, so the record lands in
    /// the sibling %ProgramData%\DeskGuest\trust\ — deliberately NOT
    /// inside the data dir, whose installer ACL grants the
    /// console user Modify (pairings/audit access). The trust
    /// directory's ACL is the installer's protected plan.</summary>
    public static string RecordPathForDataDir(string dataDir)
    {
        var parent = Path.GetDirectoryName(dataDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var root = string.IsNullOrWhiteSpace(parent) ? dataDir : parent;
        return Path.Combine(root, TrustDirName, RecordFileName);
    }

    /// <summary>The ONE path the Agent reads (Windows production
    /// shape): derived from the fixed CommonApplicationData root,
    /// NEVER from the Agent's image path, its working directory,
    /// or any environment variable a launcher controls. (An
    /// DESKGUEST_DATA_DIR-customised Core publishes the record here as
    /// well as beside its data dir — see InstallTrustRecordChannel.)</summary>
    public static string FixedRecordPath() =>
        RecordPathForDataDir(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DeskGuest", "data"));

    // ---- Record content ---------------------------------------

    public static string SerializeRecord(InstallTrustRecord record) =>
        JsonSerializer.Serialize(new
        {
            version = RecordVersion,
            corePublicKey = record.CorePublicKeyBase64,
            agentImagePath = record.AgentImagePath,
            coreImagePath = record.CoreImagePath,
        });

    /// <summary>Parse + validate record content. ANY defect —
    /// malformed JSON, wrong version, a small-order or malformed
    /// public key, a non-fully-qualified or non-.exe image path —
    /// returns null (malformed ⇒ fail closed).</summary>
    public static InstallTrustRecord? TryParseRecord(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return null;
        try
        {
            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            if (!root.TryGetProperty("version", out var v) || v.GetString() != RecordVersion) return null;
            if (!root.TryGetProperty("corePublicKey", out var k) || k.ValueKind != JsonValueKind.String) return null;
            var key = CoreIdentity.TryParsePinnedPublicKey(k.GetString());
            if (key is null) return null;
            if (!root.TryGetProperty("agentImagePath", out var a) || a.ValueKind != JsonValueKind.String) return null;
            if (!root.TryGetProperty("coreImagePath", out var c) || c.ValueKind != JsonValueKind.String) return null;
            var agent = a.GetString();
            var core = c.GetString();
            if (!IsPlausibleImagePath(agent) || !IsPlausibleImagePath(core)) return null;
            return new InstallTrustRecord(key, agent!, core!);
        }
        catch (JsonException) { return null; }
    }

    private static bool IsPlausibleImagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        // Windows shape (the production shape): fully-qualified
        // Windows path naming an .exe. Host shape (the Linux
        // harness composing a CoreRuntime over temp dirs): any
        // fully-qualified host path. The record's integrity comes
        // from its store ACL, never from this plausibility gate —
        // the gate exists so a malformed record fails closed
        // instead of comparing against nonsense.
        if (WindowsPath.IsFullyQualified(path))
            return WindowsPath.FileName(path).EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        return Path.IsPathFullyQualified(path);
    }

    private static bool IsEstablishableImagePath(string? path) =>
        !string.IsNullOrWhiteSpace(path)
        && (WindowsPath.IsFullyQualified(path) || Path.IsPathFullyQualified(path));

    /// <summary>Read a record file's content. Absent and
    /// unreadable both return null — the caller names the state
    /// (absent) and fails closed either way.</summary>
    public static string? TryReadRecordContent(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch { return null; }
    }

    // ---- Store ACL plan + compliance --------------------------

    /// <summary>The record file's ACL plan: SYSTEM +
    /// Administrators full control; the console user READ ONLY
    /// (the Agent runs as that user). No other principal, and the
    /// console user gets no write, delete, or ACL-change right —
    /// by construction of the plan. Null when no console user is
    /// known (the Core then provisions SYSTEM+Admins only and the
    /// status names it).</summary>
    public static IReadOnlyList<IpcTokenFileAclEntry> BuildRecordAclPlan(string? consoleUserSid)
    {
        var entries = new List<IpcTokenFileAclEntry>
        {
            new(IpcTokenFile.SystemSid, "FullControl", IsSystem: true),
            new(CoreIdentity.AdministratorsSid, "FullControl", IsSystem: true),
        };
        if (!string.IsNullOrWhiteSpace(consoleUserSid)
            && !string.Equals(consoleUserSid.Trim(), IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(consoleUserSid.Trim(), CoreIdentity.AdministratorsSid, StringComparison.OrdinalIgnoreCase))
            entries.Add(new IpcTokenFileAclEntry(consoleUserSid.Trim(), "Read", IsSystem: false));
        return entries;
    }

    /// <summary>Map a REAL FileSystemRights value (read from a live
    /// ACL by the Agent's platform layer) into the ACL vocabulary
    /// ClassifyStore consumes: "FullControl", "Write", or "Read".
    /// THE COMPOSITE TRAP this function exists to avoid:
    /// FileSystemRights.Modify, ReadAndExecute and Read are
    /// COMPOSITE values — Modify's bit pattern CONTAINS every Read
    /// bit (Modify = ReadAndExecute | Write | Delete), so a mask
    /// test like (rights &amp; Modify) != 0 is true for a pure read
    /// grant. The write test below therefore names only pure write
    /// bits (Write is itself a pure-write composite: WriteData |
    /// AppendData | WriteExtendedAttributes | WriteAttributes).
    /// R1 LIVE FAILURE (2026-11-26): the Agent's inline mapping
    /// included Modify in its write mask, so the trust record's
    /// console-user Read grant mapped to "Write", the protected
    /// store misclassified as unprotected, and the Agent refused
    /// its own Core (install_trust_record:store-untrusted) on the
    /// first service-shape install. The unit tests of the era
    /// built ACL entries from vocabulary strings directly and
    /// never exercised the live mapping — this function is the
    /// single shared mapping so the tested code IS the live code
    /// (pinned by the W36 tests from real FileSystemRights
    /// values).</summary>
    public static string MapRightsVocabulary(System.Security.AccessControl.FileSystemRights rights) =>
        rights.HasFlag(System.Security.AccessControl.FileSystemRights.FullControl) ? "FullControl"
        : (rights & (System.Security.AccessControl.FileSystemRights.Write
            | System.Security.AccessControl.FileSystemRights.Delete
            | System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles
            | System.Security.AccessControl.FileSystemRights.ChangePermissions
            | System.Security.AccessControl.FileSystemRights.TakeOwnership)) != 0 ? "Write"
        : "Read";

    private static bool IsPrivilegedSid(string? sid) =>
        string.Equals(sid, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase)
        || string.Equals(sid, CoreIdentity.AdministratorsSid, StringComparison.OrdinalIgnoreCase);

    private static bool IsWriteLike(string rights) =>
        rights.Contains("FullControl", StringComparison.OrdinalIgnoreCase)
        || rights.Contains("Write", StringComparison.OrdinalIgnoreCase)
        || rights.Contains("Delete", StringComparison.OrdinalIgnoreCase)
        || rights.Contains("Modify", StringComparison.OrdinalIgnoreCase)
        || rights.Contains("ChangePermissions", StringComparison.OrdinalIgnoreCase)
        || rights.Contains("TakeOwnership", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the service shape is IN FORCE for the
    /// decision (W35): the service is Running, or its state is
    /// Unknown (installed but unreadable — fail closed). A
    /// Stopped or absent service is NOT in force.</summary>
    public static bool ServiceInForce(InstallTrustServiceState serviceState) =>
        serviceState is InstallTrustServiceState.Running or InstallTrustServiceState.Unknown;

    /// <summary>Classify the record STORE from its owner + ACL
    /// entries (the platform layer reads the real FileSecurity;
    /// this pure function decides). Protected requires a
    /// privileged owner AND no write-like grant to any
    /// non-privileged principal. W35 detection rule, exact:
    ///   * A provably protected store is ProtectedService
    ///     REGARDLESS of service state (the protected record is
    ///     the service shape's anchor even while the service is
    ///     stopped — only SYSTEM/Admins could have written it).
    ///   * Service RUNNING (or state Unknown) + a store that is
    ///     not provably protected is Untrusted — the anomaly
    ///     stays fail-closed: a running SYSTEM Core re-asserts
    ///     its own protected record, so a console-owned record
    ///     in that state is wrong.
    ///   * Service NOT running + a record owned by the Agent's
    ///     own (console) user is the console-host shape's record
    ///     (named limit). A record owned by a THIRD user is
    ///     Untrusted in every shape.</summary>
    public static InstallTrustPosture ClassifyStore(
        string? ownerSid, IReadOnlyList<IpcTokenFileAclEntry>? entries, string? currentUserSid,
        InstallTrustServiceState serviceState)
    {
        var protectedStore = IsPrivilegedSid(ownerSid)
            && entries is not null
            && entries.All(e => IsPrivilegedSid(e.Sid) || !IsWriteLike(e.Rights));
        if (protectedStore) return InstallTrustPosture.ProtectedService;
        if (ServiceInForce(serviceState)) return InstallTrustPosture.Untrusted;
        return !string.IsNullOrWhiteSpace(currentUserSid)
            && string.Equals(ownerSid, currentUserSid, StringComparison.OrdinalIgnoreCase)
            ? InstallTrustPosture.ConsoleHost
            : InstallTrustPosture.Untrusted;
    }

    /// <summary>W28-era signature, kept for callers/tests written
    /// against it: serviceShape:true maps to Running (the old
    /// key-existence reading, conservative), false to
    /// NotInstalled. New code uses the service-state overload.</summary>
    public static InstallTrustPosture ClassifyStore(
        string? ownerSid, IReadOnlyList<IpcTokenFileAclEntry>? entries, string? currentUserSid, bool serviceShape) =>
        ClassifyStore(ownerSid, entries, currentUserSid,
            serviceShape ? InstallTrustServiceState.Running : InstallTrustServiceState.NotInstalled);

    // ---- Canonicalisation -------------------------------------

    /// <summary>Canonicalise an image path for comparison:
    /// resolve filesystem links component by component (the
    /// injected resolver maps one path prefix to its link target,
    /// or null when the prefix is not a link — tests inject a
    /// fake; the platform default uses the real filesystem), then
    /// lexical canonicalisation. Bounded: at most 16 link hops
    /// per component walk, so a link loop terminates on the
    /// un-resolved spelling instead of spinning.</summary>
    public static string CanonicalizeImagePath(string path, Func<string, string?>? linkResolver = null)
    {
        var resolve = linkResolver ?? DefaultLinkResolver;
        var p = WindowsPath.Normalize(path);
        var isUnc = p.StartsWith(@"\\", StringComparison.Ordinal);
        var rooted = !isUnc && p.StartsWith('\\');
        var segments = p.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        // Rebuild progressively, resolving each prefix: a link at
        // ANY component (a symlinked exe, a junctioned directory)
        // rewrites the prefix, and the walk restarts on the
        // rewritten path so chains resolve fully.
        for (var hop = 0; hop < 16; hop++)
        {
            var rebuilt = RebuildResolvingPrefixes(segments, isUnc, rooted, resolve,
                out var changed, out var newIsUnc, out var newRooted);
            segments = rebuilt;
            isUnc = newIsUnc;
            rooted = newRooted;
            if (!changed) break;
        }
        return WindowsPath.Canonicalize(JoinSegments(segments, isUnc, rooted));
    }

    private static string JoinSegments(string[] segments, bool isUnc, bool rooted)
    {
        if (segments.Length == 0) return rooted ? "\\" : "";
        if (isUnc) return @"\\" + string.Join('\\', segments);
        if (segments[0].EndsWith(':')) return segments[0] + "\\" + string.Join('\\', segments.Skip(1));
        return (rooted ? "\\" : "") + string.Join('\\', segments);
    }

    private static string[] RebuildResolvingPrefixes(string[] segments, bool isUnc, bool rooted, Func<string, string?> resolve,
        out bool changed, out bool newIsUnc, out bool newRooted)
    {
        changed = false;
        newIsUnc = isUnc;
        newRooted = rooted;
        var current = new List<string>();
        for (var i = 0; i < segments.Length; i++)
        {
            current.Add(segments[i]);
            var prefix = JoinSegments(current.ToArray(), isUnc, rooted);
            string? target = null;
            try { target = resolve(prefix); } catch { target = null; }
            if (!string.IsNullOrWhiteSpace(target))
            {
                changed = true;
                var normalizedTarget = WindowsPath.Normalize(target);
                newIsUnc = normalizedTarget.StartsWith(@"\\", StringComparison.Ordinal);
                newRooted = !newIsUnc && normalizedTarget.StartsWith('\\');
                var targetSegments = normalizedTarget.Split('\\', StringSplitOptions.RemoveEmptyEntries);
                var rest = segments.Skip(i + 1);
                return targetSegments.Concat(rest).ToArray();
            }
        }
        return segments;
    }

    /// <summary>The real-filesystem link resolver: a path prefix
    /// that IS a symlink / junction resolves to its final target;
    /// anything else (or any failure) is not a link. Off-Windows
    /// the same FileSystemInfo link APIs apply to POSIX symlinks,
    /// which is how the harness proves the walk.</summary>
    private static string? DefaultLinkResolver(string prefix)
    {
        try
        {
            // Prefixes are built in Windows spelling; probe the
            // filesystem in the host's own spelling (identical on
            // Windows, separator-translated on the POSIX harness).
            var fsPath = prefix.Replace('\\', Path.DirectorySeparatorChar);
            FileSystemInfo? info = Directory.Exists(fsPath) ? new DirectoryInfo(fsPath) : File.Exists(fsPath) ? new FileInfo(fsPath) : null;
            if (info?.LinkTarget is null) return null;
            var target = info.ResolveLinkTarget(returnFinalTarget: true);
            return target?.FullName;
        }
        catch { return null; }
    }

    // ---- The Agent decision ------------------------------------

    /// <summary>THE Agent decision (W28), pure so the harness
    /// pins the exact logic the Session Agent runs: given the
    /// record content read from the FIXED record path, the
    /// store's owner/ACL facts, the deployment shape, this
    /// process's own image path, and the DESKGUEST_CORE_EXE override,
    /// decide whether this Agent may authenticate at all, and
    /// against which pin + registered Core path. Every refusal
    /// names its state for the audit log.</summary>
    /// <summary>W28-era signature, kept: serviceShape:true maps
    /// to Running, false to NotInstalled (see the ClassifyStore
    /// bool overload). New code uses the service-state overload.</summary>
    public static InstallTrustDecision Evaluate(
        string? recordContent,
        string? storeOwnerSid,
        IReadOnlyList<IpcTokenFileAclEntry>? storeEntries,
        string? currentUserSid,
        bool serviceShape,
        string? agentImagePath,
        string? coreExeOverride,
        Func<string, string?>? linkResolver = null) =>
        Evaluate(recordContent, storeOwnerSid, storeEntries, currentUserSid,
            serviceShape ? InstallTrustServiceState.Running : InstallTrustServiceState.NotInstalled,
            agentImagePath, coreExeOverride, linkResolver);

    public static InstallTrustDecision Evaluate(
        string? recordContent,
        string? storeOwnerSid,
        IReadOnlyList<IpcTokenFileAclEntry>? storeEntries,
        string? currentUserSid,
        InstallTrustServiceState serviceState,
        string? agentImagePath,
        string? coreExeOverride,
        Func<string, string?>? linkResolver = null)
    {
        if (recordContent is null)
            return new InstallTrustDecision(false, InstallTrustRefusal.RecordAbsent,
                "install_trust_record:absent", InstallTrustPosture.Untrusted, null);
        var record = TryParseRecord(recordContent);
        if (record is null)
            return new InstallTrustDecision(false, InstallTrustRefusal.RecordMalformed,
                "install_trust_record:malformed", InstallTrustPosture.Untrusted, null);
        var posture = ClassifyStore(storeOwnerSid, storeEntries, currentUserSid, serviceState);
        if (posture == InstallTrustPosture.Untrusted)
            return new InstallTrustDecision(false, InstallTrustRefusal.RecordStoreUntrusted,
                "install_trust_record:store-untrusted", posture, null);
        if (!IsEstablishableImagePath(agentImagePath))
            return new InstallTrustDecision(false, InstallTrustRefusal.AgentNotRegistered,
                "install_trust_record:agent-path-unestablishable", posture, null);
        var ownCanonical = CanonicalizeImagePath(agentImagePath, linkResolver);
        var registeredCanonical = CanonicalizeImagePath(record.AgentImagePath, linkResolver);
        if (!string.Equals(ownCanonical, registeredCanonical, StringComparison.OrdinalIgnoreCase))
            return new InstallTrustDecision(false, InstallTrustRefusal.AgentNotRegistered,
                "install_trust_record:agent-not-registered", posture, null);
        if (!string.IsNullOrWhiteSpace(coreExeOverride)
            && !WindowsPath.EqualsCanonical(
                CanonicalizeImagePath(coreExeOverride, linkResolver),
                CanonicalizeImagePath(record.CoreImagePath, linkResolver)))
            return new InstallTrustDecision(false, InstallTrustRefusal.CoreOverrideOutsideRecord,
                "install_trust_record:core-override-outside-record", posture, null);
        return new InstallTrustDecision(true, InstallTrustRefusal.None,
            posture == InstallTrustPosture.ProtectedService
                ? "install_trust_record:ok"
                : "install_trust_record:ok-console-host-named-limit",
            posture, record);
    }

    /// <summary>Whether the Agent's pipe-host image-path leg may
    /// stand down when the pipe server process could not be opened
    /// for inspection (W37, R1 live failure 2026-11-26). In the
    /// ProtectedService shape the Core runs as LocalSystem and the
    /// Agent as the interactive user; the OS denies the user any
    /// handle to the service process, so the image leg is
    /// UNEXECUTABLE in exactly the shape the record exists for —
    /// the W28–W36 suites never met it because they exercise the
    /// decision logic, not the live cross-principal OS call. The
    /// stand-down is safe ONLY because the legs that remain are
    /// strictly stronger than an image-path string: the record
    /// store's protection (evaluated by Evaluate), the SCM service
    /// state behind the posture, and the W25 identity signature
    /// the host must still produce against the record's pinned
    /// key — a pipe squatter without the SYSTEM-protected identity
    /// key cannot pass it. Every other posture keeps the image
    /// leg mandatory: in the ConsoleHost shape host and Agent
    /// share a user, the handle opens, and the leg is that
    /// shape's main anti-squatter proof.</summary>
    public static bool MaySkipCoreImageCheck(InstallTrustPosture posture)
        => posture == InstallTrustPosture.ProtectedService;

    /// <summary>The expected Core image paths under a record:
    /// exactly the registered Core path. DESKGUEST_CORE_EXE may only
    /// SELECT it (an override equal to it narrows to it; any
    /// other override establishes NOTHING — empty, fail closed).
    /// Supersedes the W25 co-located set for Agents that hold a
    /// record; the co-located ExpectedCoreImagePaths remains for
    /// the legacy surface only and is no longer consulted by the
    /// Agent handshake.</summary>
    public static IReadOnlyList<string> ExpectedCoreImagePaths(InstallTrustRecord record, string? coreExeOverride)
    {
        if (!string.IsNullOrWhiteSpace(coreExeOverride))
            return WindowsPath.EqualsCanonical(coreExeOverride, record.CoreImagePath)
                ? new[] { record.CoreImagePath }
                : Array.Empty<string>();
        return new[] { record.CoreImagePath };
    }

    /// <summary>Record-based pipe-server image check: the
    /// observed server image, canonicalised, must equal the
    /// registered Core image path, canonicalised.</summary>
    public static bool IsCoreServerImage(string? imagePath, InstallTrustRecord record, string? coreExeOverride = null,
        Func<string, string?>? linkResolver = null)
    {
        if (!IsEstablishableImagePath(imagePath)) return false;
        var expected = ExpectedCoreImagePaths(record, coreExeOverride);
        if (expected.Count == 0) return false;
        var observed = CanonicalizeImagePath(imagePath, linkResolver);
        return expected.Any(e => string.Equals(observed, CanonicalizeImagePath(e, linkResolver), StringComparison.OrdinalIgnoreCase));
    }
}
