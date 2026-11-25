using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Acp.Core.Ipc;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Core.Phase2;
using Acp.Core.Platform;
using Acp.Core.Services;
using Acp.Shared.AiPack;
using Acp.Shared.Audit;
using Acp.Shared.Connection;
using Acp.Shared.Enrollment;
using Acp.Shared.Heartbeat;
using Acp.Shared.Hub;
using Acp.Shared.Ipc;
using Acp.Shared.State;
using Acp.Shared.Policy;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.OwnPath;
using Acp.Shared.QuickAssist;
using Acp.Shared.Sessions;
using Acp.Shared.Tailscale;
using Acp.Shared.Terminal;
using Acp.Shared.WebRtc;
using Acp.Shared.Tools;
using Acp.Shared.Transport;
using Acp.Shared.Wake;
using Microsoft.Extensions.Hosting;

namespace Acp.Core;

/// <summary>Composition options. Production values come from the
/// installer (ProgramData data dir, product port 8741); tests override.</summary>
public sealed record CoreOptions
{
    public required string DataDir { get; init; }
    public int Port { get; init; } = 8741;
    public IReadOnlyList<string> FileRoots { get; init; } = Array.Empty<string>();
    public string AgentExePath { get; init; } = "AcpSessionAgent.exe";
    public bool IncludeLoopbackLane { get; init; } = false; // dev/tests only
    /// <summary>Hub rung (D16/D27): the hub component runs ONLY when a scope
    /// chose the hub rung. Default false — dormant, nothing runs.</summary>
    public bool HubRungSelected { get; init; } = false;
    public string HubServerUrl { get; init; } = "https://127.0.0.1:8085";
    public ISecretProtector? Protector { get; init; }
    /// <summary>W15 / DS-P9-F6: explicit DEV opt-in for the ephemeral
    /// update-signing key. Default FALSE, and Program.cs (the
    /// production composition) never sets it: without a pinned
    /// product key file (update-key.pub) the update surface FAILS
    /// CLOSED with a named refusal instead of running on a fresh
    /// in-process keypair. When true (or the dedicated
    /// ACP_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1 — W19/DS-B-17: the
    /// update posture's OWN switch, decided canonically by
    /// DevEphemeralUpdateKeyOptIn; the IPC variable
    /// ACP_DEV_ALLOW_NO_TOKEN no longer reaches this posture),
    /// the ephemeral verifier is used and labelled "dev-ephemeral"
    /// in the status report and the audit chain — never silently
    /// interchangeable with the pinned product key.</summary>
    public bool AllowDevEphemeralUpdateKey { get; init; } = false;
    /// <summary>W30 / D-DEC-7: the install root — custody home of
    /// the runtime pointer-signing private seed and its public pin
    /// (outside the data dir by construction; PointerSigningCustody
    /// refuses by name otherwise). Null = no pointer-signing
    /// custody is composed and pointers stay in the named
    /// LEGACY-UNKEYED posture. Program.cs supplies it (the
    /// launcher passes ACP_INSTALL_ROOT to the Core it execs from
    /// a slot, whose own base directory is inside the data dir).</summary>
    public string? InstallRoot { get; init; }
    /// <summary>W35 test seam: when set, this sink receives the
    /// pointer_signing_posture append INSTEAD of
    /// Enterprise.AppendServiceAudit, so a test can force the
    /// append to fail and prove the failure surfaces (see
    /// CoreRuntime.PointerSigningPostureAuditState). Production
    /// composition (Program.cs) never sets it.</summary>
    public Action<string, string?, string>? PointerSigningPostureAuditSink { get; init; }
    /// <summary>W36 test seam: as PointerSigningPostureAuditSink,
    /// for the update_signing_posture append (Item 3: the W35
    /// treatment applied to the neighbouring append). Production
    /// composition never sets it.</summary>
    public Action<string, string?, string>? UpdateSigningPostureAuditSink { get; init; }
    /// <summary>W113 test seam: when set, this probe replaces the
    /// production process enumeration (CoreProcessLiveness.Probe)
    /// for the death-proof check in the CoreRuntime constructor,
    /// so a test can stage another-Core-running / indeterminate
    /// verdicts without a second real Core process. Production
    /// composition (Program.cs) never sets it.</summary>
    public Func<Acp.Shared.Heartbeat.CoreProcessLiveness.Result>? CoreLivenessProbe { get; init; }
    public ILaneAddressProbe? Probe { get; init; }
    public IClock? Clock { get; init; }
    public IProcessRunner? Runner { get; init; }
    public IFactChecks? FactChecks { get; init; }
    public IAgentLauncher? AgentLauncher { get; init; }
    public TimeSpan SupervisorPeriod { get; init; } = TimeSpan.FromSeconds(1);
}

/// <summary>
/// The Core runtime: composition root + supervisor loop. Everything the
/// design promises at Phase 0 is wired here — policy choke point, audit,
/// lane supervision, agent IPC + watchdog, STOP file, heartbeat/last-word.
/// Runs as a Windows Service on the laptop (Program.cs) and as a plain
/// hosted service in the Linux test suite.
/// </summary>
public sealed class CoreRuntime : IHostedService, IAsyncDisposable
{
    private readonly CoreOptions _options;
    private readonly CancellationTokenSource _cts = new();

    public CoreState State { get; } = new();
    public PairingService Pairings { get; }
    public DeviceIdentity Identity { get; private set; }
    // C20 wiring: the owner-local recovery acts (export/restore) —
    // constructed after the audit log + event bus exist; reached ONLY
    // from the companion-window IPC channel (see ApplyRecoveryAction).
    public Services.OwnerRecoveryService Recovery { get; private set; } = null!;
    private ISecretProtector _protector = null!;
    private string _identityPath = "";
    private bool _identityMintedThisRun;
    /// <summary>W113: when this Core started on the operator's
    /// one-time liveness override (indeterminate enumeration),
    /// the detail to write into the audit chain at StartAsync;
    /// null on every ordinary start.</summary>
    private string? _livenessOverrideAuditDetail;
    public EnrollmentService Enrollments { get; }
    public RosterService Roster { get; }
    public SessionService HumanSessions { get; }
    // Transport core (Block C part 1): the failover engine over the
    // live roster/session stores, and the LAN host listener. The
    // listener is constructed DORMANT — it opens no socket until an
    // operator act from the host window starts it (D29 discipline).
    public TransportSessionManager Transports { get; }
    public LanHostListener LanListener { get; }
    // Block C part 3: the hub host listener (the same enrollment
    // handshake, bound to this device's mesh address when an
    // operator starts it — dormant until then) and the in-app
    // Tailscale setup service (D4) behind the `mesh` rung.
    public LanHostListener HubListener { get; }
    public MeshSetupService MeshSetup { get; }
    // Block F surfacing: the Block E enterprise services live in the
    // Core, the session terminal authority, quick-assist codes, the
    // manual-WebRTC signaling, and the local AI pack machinery.
    public Services.EnterpriseService Enterprise { get; }
    // Block R foundation (RMM-03 + RMM-07): the signed-command
    // verify-gate (null when no customer command key is configured
    // — the named pre-RMM-03 posture, never implied coverage) and
    // the management-policy service (Effective Policy data surface).
    public Shared.Security.SignedCommandGate? CommandGate { get; private set; }
    public Services.ManagementPolicyService ManagementPolicies { get; private set; } = null!;
    // RMM-02: the patch-management service (catalogue, approvals,
    // rings, endpoint-signed PatchRun journal + P2P fetch path).
    public Services.PatchService Patches { get; private set; } = null!;
    // RMM-05: the vulnerability-management service (local feed
    // cache, scanner imports, exposure work items) over the hub
    // inventory store. The store is hub-side state: device reports
    // land in it through the RMM-04 hub integration; it starts
    // empty here rather than inventing a fleet.
    public Shared.Inventory.InventoryStore HubInventory { get; } = new();
    public Services.VulnerabilityService Vulnerabilities { get; private set; } = null!;
    // RMM-12: the work-item layer (alert→work→session→audit trail).
    // The service IS RMM-01's IWorkItemSink; session attachments are
    // validated against the existing session record (HumanSessions).
    // No webhook transport is wired here — bridge deliveries stay in
    // their visible states until hub wiring supplies one.
    public Services.WorkItemService WorkItems { get; private set; } = null!;
    // RMM-18: disk-encryption enforcement + recovery-key escrow.
    // Lane A wired the production BitLockerDriver (manage-bde):
    // state is parsed from the OS tool, enables run it, and off a
    // Windows host every answer is UNKNOWN / refused by name —
    // never a fabricated "encrypted". Escrow keys are sealed by
    // the runtime ISecretProtector (DPAPI on Windows).
    public Services.EncryptionEnforcementService EncryptionEnforcement { get; private set; } = null!;
    // Block R closing integration (2026-11-21): the RMM services the
    // lanes built at model/service level, wired into the runtime.
    // Honest-stub rule: where no production dependency exists on this
    // host (OS appliers, directory connector, probe transport, backup
    // capture, imaging), the service is bound to the lane's own
    // Unavailable/Fake shape, which refuses BY NAME — never a silent
    // pretend success. Each such binding is named in the integration log.
    public Shared.Monitoring.HealthAlertCentre AlertCentre { get; private set; } = null!;
    public Shared.Monitoring.HubHealthIngest HubHealth { get; private set; } = null!;
    public Services.EndpointMonitorService Monitor { get; private set; } = null!;
    public Services.HubInventoryService HubInventorySvc { get; private set; } = null!;
    public Shared.Inventory.UnmanagedAssetRegister UnmanagedRegister { get; private set; } = null!;
    public Services.BackupService Backups { get; private set; } = null!;
    public Services.RemediationService Remediation { get; private set; } = null!;
    public Services.ComplianceService Compliance { get; private set; } = null!;
    public Shared.BackgroundTools.BackgroundToolsService BackgroundTools { get; private set; } = null!;
    public Services.NetworkDiscoveryService NetworkDiscovery { get; private set; } = null!;
    public Services.ReportingService Reporting { get; private set; } = null!;
    public Services.ReportingHttpListener ReportingHttp { get; private set; } = null!;
    public Services.RunbookService Runbooks { get; private set; } = null!;
    public Services.HealthScoringService HealthScoring { get; private set; } = null!;
    public Services.AnomalyDetectionService AnomalyDetection { get; private set; } = null!;
    public Services.EndpointSecurityService EndpointSecurity { get; private set; } = null!;
    public Services.BaselineDriftService BaselineDrift { get; private set; } = null!;
    public Services.SoftwareMeteringService SoftwareMetering { get; private set; } = null!;
    public Services.VendorPassService VendorPasses { get; private set; } = null!;
    public Services.BrowserPolicyService BrowserPolicy { get; private set; } = null!;
    public Services.AppControlService AppControl { get; private set; } = null!;
    public Services.PeripheralControlService PeripheralControl { get; private set; } = null!;
    public Services.MdmSubsetService MdmSubset { get; private set; } = null!;
    public Services.DlpService Dlp { get; private set; } = null!;
    public Services.DirectoryEnrollmentService DirectoryEnrollment { get; private set; } = null!;
    public Services.MobileOperatorService MobileOperator { get; private set; } = null!;
    public Shared.SiteDocs.SiteDocumentationService SiteDocumentation { get; private set; } = null!;
    public Services.ProvisioningService Provisioning { get; private set; } = null!;
    public Shared.CameraShare.CameraShareService CameraShares { get; private set; } = null!;
    public Shared.NetworkDiscovery.CameraViewService CameraViewing { get; private set; } = null!;
    // Lane A: the hub-side RMM-16 package repository + its secret
    // vault (vault values are protector-sealed and never persisted
    // by the repository export — refs + hashes only).
    public Shared.Deployment.PackageSecretVault HubPackageVault { get; private set; } = null!;
    public Shared.Deployment.PackageRepository HubPackages { get; private set; } = null!;
    /// <summary>W5 host wiring: the RMM-16 deployment service,
    /// composed over HubPackages/HubPackageVault with the
    /// production verify_install probe (ProductionInstalledVersionProbe).</summary>
    public Services.SoftwareDeploymentService SoftwareDeployments { get; private set; } = null!;
    /// <summary>W5 host wiring (BD-WIN-CORE-3/F1): the authenticated
    /// mesh identity resolver (pairing bearer token → roster user).</summary>
    public Services.MeshIdentityResolver MeshIdentity { get; private set; } = null!;
    // Lane A (item 3): the provisioned hub signing key for FL-28a
    // health-score snapshot signatures (null until provisioned —
    // imports then stay hash+integrity only, as before).
    public Services.HubSigningKeyProvisioning HubSigningKeys { get; private set; } = null!;

    /// <summary>W3 host wiring (5): ENTERPRISE OPT-IN --
    /// requireSigned for hub job-state reports
    /// (BD-SHARED-RMM-2/F10's JobStateReconciler seam). DEFAULT
    /// OFF (false): a stock host accepts unsigned job-state
    /// reports over the authenticated paired transport, exactly
    /// as before. An enterprise host sets this to true (code
    /// opt-in at composition) and builds its reconciler through
    /// CreateJobStateReconciler(), after which UNSIGNED reports
    /// refuse by name. Named here, in code, deliberately: there
    /// is no policy key for it, so no policy document can flip
    /// it remotely.</summary>
    public bool EnterpriseRequireSignedJobReports { get; set; } = false;

    /// <summary>Build the hub job-state reconciler honouring
    /// EnterpriseRequireSignedJobReports (W3 wiring item 5).</summary>
    public Shared.Jobs.JobStateReconciler CreateJobStateReconciler() =>
        new(() => DateTimeOffset.UtcNow,
            id => Enrollments.List().Any(d => !d.Revoked &&
                string.Equals(d.DeviceId, id, StringComparison.OrdinalIgnoreCase)),
            requireSigned: EnterpriseRequireSignedJobReports);
    private Shared.Security.CustomerCommandKeyRing? _commandKeyRing;
    public TerminalService Terminals { get; }
    public QuickAssistService QuickAssist { get; }
    public WebRtcSignaling WebRtc { get; }
    public AiPackService AiPack { get; }
    /// <summary>W19-C: the product's pack home — the AiPack download
    /// act's ONLY target, composed from the Core's data dir
    /// (&lt;dataDir&gt;/aipack/&lt;packId&gt;), never a hardcoded
    /// drive: the W18 deploy's D: staging was a laptop workaround
    /// for a full C:, not the product default.</summary>
    public string AiPackHome { get; private set; } = "";
    /// <summary>W19-C: TOTAL POLICY CONTROL keys for the two acts
    /// wired in this wave (registered in FeatureToggleRegistry.Seeded
    /// — a feature without its toggle is unfinished).</summary>
    public const string TorProvisioningPolicyKey = "rmm.tor_provisioning.enabled";
    public const string AiPackDownloadPolicyKey = "rmm.aipack_download.enabled";
    // Block G (2026-11-20): the completeness-sweep services — wake
    // registry (G-01), standalone transfers (G-04), local second
    // factor (G-06), session tunnels (G-08). The session-surface
    // flags (G-02/G-03/G-07) and calls (G-05) live on HumanSessions
    // itself. Every one of these is policy-gated through
    // Enterprise.CheckFeature (TOTAL POLICY CONTROL).
    public WakeService Wake { get; }
    public StandaloneTransferService StandaloneTransfers { get; }
    public SecondFactorService SecondFactors { get; }
    public SessionTunnelService SessionTunnels { get; }
    public PolicyEngine Policy { get; } = new();
    public ToolRegistry Tools { get; } = new();
    public FileAuditLog Audit { get; }
    public AgentIpcServer Ipc { get; }
    public LaneSupervisor Lanes { get; }
    public LaneHostManager LaneHosts { get; }
    public SessionManager Sessions { get; } = new();
    public Services.StreamService Stream { get; }
    public Services.MeshService Mesh { get; }
    public AgentWatchdog Watchdog { get; }
    /// <summary>W20: the token-file channel's publish status for
    /// this boot (metadata only — never the token): published with
    /// its ACL plan, refused by name, or failed by name.</summary>
    public string IpcTokenFileStatus { get; private set; } = "not-published";

    /// <summary>W30: the runtime pointer-signing posture for this
    /// boot (metadata only — fingerprint and paths, never seed
    /// material): keyed with its custody named, refused by name,
    /// or not composed (LEGACY-UNKEYED).</summary>
    public string PointerSigningStatus { get; private set; } = "not-composed";

    /// <summary>W37: the compliance-pack keyed-anchoring posture
    /// for this boot: the SAME runtime custody as pointer signing
    /// key-anchors compiled packs (PackAuditAnchor), refused by
    /// name, or not composed (LEGACY-UNKEYED-PACK).</summary>
    public string PackSigningStatus { get; private set; } = "not-composed";

    /// <summary>W35: whether the pointer_signing_posture append
    /// actually LANDED in the enterprise chain. W33-B found the
    /// append swallowed by a try/catch in composition (keying
    /// began live, zero "pointer" entries in the chain). Now:
    /// "recorded:pointer_signing_posture" only when the entry is
    /// verified present in the chain with persistence ok;
    /// otherwise a named FAILED state — a status that cannot be
    /// recorded is an error state, never silence.</summary>
    public string PointerSigningPostureAuditState { get; private set; } = "not-attempted";

    /// <summary>W36 Item 3: the W35 named-state treatment for the
    /// neighbouring update_signing_posture append —
    /// "recorded:update_signing_posture" only when the entry is
    /// proven in the chain with persistence ok; otherwise a named
    /// FAILED state. See RecordUpdateSigningPostureAudit.</summary>
    public string UpdateSigningPostureAuditState { get; private set; } = "not-attempted";

    /// <summary>W25: the Core identity load/publish status for
    /// this boot (metadata only — never key material).</summary>
    public string CoreIdentityStatus { get; private set; } = "not-loaded";

    /// <summary>W28: the install trust record provisioning status
    /// for this boot (metadata only — a public key and paths are
    /// named by count, never printed).</summary>
    public string InstallTrustRecordStatus { get; private set; } = "not-provisioned";
    /// <summary>W20: where this Core publishes the per-boot IPC
    /// token for task-launched agents.</summary>
    public string IpcTokenFilePath => IpcTokenFile.DefaultPath(_options.DataDir);
    public RunMarker Marker { get; }
    public McpHandler Mcp { get; }
    /// <summary>W9: the per-action gate registry (design of record
    /// §3 live caller). Pending GateSheet requests live here, bound
    /// to their pairing + session, consumed by exactly one answer;
    /// session end and unpair invalidate them.</summary>
    public Shared.Ipc.GateRequestBroker GateRequests { get; } = new();

    /// <summary>W9: the Agent chat store (Addendum A parity) — one
    /// thread per pairing under the data dir's chat folder. Assigned
    /// in the constructor (the path needs the options' data dir).</summary>
    public Shared.Sessions.AgentChatStore Chat { get; private set; } = null!;

    /// <summary>W120 / S13: the order-card store — one orders file
    /// per pairing beside the thread files. Assigned in the
    /// constructor with Chat.</summary>
    public Shared.Sessions.ChatOrderStore Orders { get; private set; } = null!;

    /// <summary>W122 / N22: the owner's seen cursors over the one
    /// chat store — index metadata for the unified inbox (which
    /// agent messages the owner has been shown), beside the
    /// thread files. Assigned in the constructor with Chat.</summary>
    public Shared.Sessions.ChatSeenStore ChatSeen { get; private set; } = null!;

    /// <summary>W120 / S13: each pairing's agent-side chat read
    /// cursor (the last next_cursor a chat_read handed that
    /// pairing's agent). In-memory truth for the thread's queued
    /// count: owner messages beyond the cursor are queued for an
    /// agent that hasn't read them yet. A Core restart resets it
    /// to 0 — the queue then shows everything unread, which is
    /// the honest direction to err.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _chatAgentCursor = new();
    /// <summary>U2: the agent event channel — subscription store +
    /// bus. Producers (MCP choke point, IPC foreground reports,
    /// notify_user, link-loss) publish here; the SSE leg in
    /// McpHandler streams each pairing only its own events.</summary>
    public Shared.Sessions.EventSubscriptionStore EventSubscriptions { get; } = new();
    public Shared.Sessions.AgentEventBus AgentEvents { get; }
    public CoreSelfCheck SelfCheck { get; }
    public UpdateManager Updates { get; }
    public UnlockService Unlock { get; }
    public SafeModeOrchestrator SafeMode { get; }
    public MissionEngine Missions { get; }
    public FleetBoard Fleet { get; }
    // BD-WIN-CORE-2 wiring: the owner-side takeover API (owner-local
    // channels only — never an MCP tool) and the pairing-owned tunnel
    // service (so STOP / session-end teardown can reach it).
    public TakeoverArbiter Takeover { get; }
    public TcpTunnelService Tunnels { get; }
    public LanCertificateStore LanTls { get; }
    // Hub component (Block C part 2 — Headscale packaging, audit §8):
    // lifecycle + ACP-side enforcement (API-key vault, client floor,
    // node registry, join service). Dormant unless HubRungSelected.
    public HubLifecycle Hub { get; }
    // Tor component (A2): the setup act that provisions the pinned
    // Tor client, verifies its binary before every launch, runs it
    // as a local-only SOCKS listener, and writes the tor.json the
    // `tor` rung reads. Dormant until the act runs.
    public Shared.Tor.TorSetupService TorSetup { get; }
    public HubApiKeyVault HubApiKeys { get; }
    public HubNodeRegistry HubNodes { get; }
    public HubJoinService HubJoins { get; }
    private IReadOnlyList<string> _pluginErrors = Array.Empty<string>();

    private Task? _ipcTask;
    private string? _lastPresenceKey;
    private string? _lastActingAgentName;
    private Task? _supervisorTask;

    /// <summary>FR-124 / W95: the per-data-dir single-instance
    /// lock, acquired as the constructor's FIRST act (see the
    /// constructor) and held for this Core's whole lifetime. A
    /// second Core on the same data dir never gets a CoreRuntime
    /// at all — the constructor throws
    /// CoreInstanceLock.AlreadyRunningException before any store,
    /// publish, bind, or state write.</summary>
    public CoreInstanceLock InstanceLock { get; }

    public CoreRuntime(CoreOptions options)
    {
        _options = options;
        Directory.CreateDirectory(options.DataDir);
        // FR-124 / W95 (D-W93-1): the single-instance guard comes
        // BEFORE everything else in this constructor — before the
        // pairing/identity/enrollment/roster stores are read or
        // written, before the audit chain is composed, before the
        // IPC token file is published, the Core identity loaded,
        // or the trust record provisioned, and long before
        // StartAsync reads the run marker or binds a lane. A
        // duplicate Core therefore writes NOTHING: no heartbeat,
        // no run marker, no IPC token, no trust record.
        InstanceLock = CoreInstanceLock.Acquire(options.DataDir);

        // W113 (W112-C4b): the DEATH PROOF by process enumeration.
        // The marker + heartbeat check below rests on activity
        // timestamps, and both files are written by the old Core
        // itself — a suspended/stalled LIVE old Core freezes both
        // signs together, so "both stale" never proved death for
        // the pre-W95 OwnerPid=0 class (the W112 counter-example).
        // Enumeration asks the OS instead, independent of every
        // timestamp: is another DeskGuest Core PROCESS alive?
        //   * Another Core found → REFUSE, whatever the marker
        //     class (pid recorded or not, fresh or stale, cleanly
        //     ended or not): a live process outranks every file.
        //     The operator override does NOT apply — positive
        //     evidence is not overridable.
        //   * No other Core found → the previous owner is dead on
        //     evidence independent of timestamps; the marker check
        //     below then only characterizes (and, as defense in
        //     depth, a marker that still names a live RECORDED
        //     pid keeps refusing, exactly as W111 left it).
        //   * Indeterminate (enumeration failed / a process was
        //     unidentifiable) → FAIL CLOSED: refuse — unless the
        //     operator performed the named one-time override (the
        //     override file in the data folder, consumed here and
        //     audited at StartAsync; a console-operator act, never
        //     a command-line flag an agent could pass casually).
        {
            var liveness = (options.CoreLivenessProbe ?? CoreProcessLiveness.Probe)();
            if (liveness.Verdict == CoreProcessLiveness.Verdict.OtherCoreRunning)
            {
                InstanceLock.Dispose();
                throw new CoreInstanceLock.AlreadyRunningException(
                    $"{CoreInstanceLock.DuplicateMessage} (data folder: {Path.GetFullPath(options.DataDir)}" +
                    $"; process enumeration: {liveness.Detail} — a live Core process is positive evidence " +
                    "no marker or heartbeat reading can overrule, and the operator override does not apply to it)");
            }
            if (liveness.Verdict == CoreProcessLiveness.Verdict.Indeterminate)
            {
                if (CoreProcessLiveness.ConsumeOverride(options.DataDir))
                {
                    _livenessOverrideAuditDetail =
                        $"process enumeration was indeterminate ({liveness.Detail}); the start proceeded " +
                        $"on the operator's one-time override file '{CoreProcessLiveness.OverrideFileName}' " +
                        "in the data folder, consumed at this start";
                }
                else
                {
                    InstanceLock.Dispose();
                    throw new CoreInstanceLock.AlreadyRunningException(
                        $"{CoreInstanceLock.DuplicateMessage} (data folder: {Path.GetFullPath(options.DataDir)}" +
                        $"; process enumeration could not prove no other Core is running ({liveness.Detail}) — " +
                        "failing closed. If you are the operator at this console and you have verified no other " +
                        "DeskGuest Core is running, create the one-time override file named " +
                        $"'{CoreProcessLiveness.OverrideFileName}' in the data folder and start again; " +
                        "it is consumed by that start and its use is written into the audit record)");
                }
            }
        }

        // W107 (W106-verified C4b): the upgrade-coexistence check.
        // The lock being free does NOT prove the data dir is free:
        // a pre-W95 Core holds no lock file at all, so an in-place
        // upgrade could acquire the lock and boot ALONGSIDE a live
        // old Core on the same data dir (the W93 duplicate defect
        // surviving the upgrade path). The old build's run marker
        // is the evidence it does emit: if the marker is fresh (a
        // live Core beats it every ~30 s) and its owner cannot be
        // verified dead — a live pid, an indeterminate check, or a
        // pre-W95 marker with OwnerPid=0 and no liveness evidence
        // at all — this Core REFUSES with the same discipline as
        // the lock refusal (AlreadyRunningException → Program.cs
        // prints the clear line, leaves its own record, exits 41),
        // before any store/publish below. A marker whose owner is
        // provably dead (pid gone, or pid recycled to a younger
        // process) never blocks: the legitimate restart.
        {
            var markerProbe = new RunMarker(Path.Combine(options.DataDir, "run-marker.json"));
            var snapshot = markerProbe.Inspect();
            // W111 (W110-C4b): marker age alone is NOT the liveness
            // verdict — a live-but-stalled owner (suspend/resume,
            // long stall) has a stale marker. The check also reads
            // the pid's own life and heartbeat.json's freshness;
            // a start proceeds only when the owner is provably
            // dead on every available sign.
            var heartbeatAt = RunMarker.ReadHeartbeatAtUtc(options.DataDir);
            if (snapshot is not null && RunMarker.IndicatesLiveOwner(snapshot, DateTimeOffset.UtcNow, heartbeatAt))
            {
                InstanceLock.Dispose();
                throw new CoreInstanceLock.AlreadyRunningException(
                    $"{CoreInstanceLock.DuplicateMessage} (data folder: {Path.GetFullPath(options.DataDir)}" +
                    $"; live run marker: owner pid {(snapshot.OwnerPid > 0 ? snapshot.OwnerPid.ToString() : "unknown (pre-single-instance build)")}" +
                    $", last seen {snapshot.LastSeenUtc:u}, heartbeat {(heartbeatAt is { } hb ? hb.ToString("u") : "absent")}, not ended cleanly — the running Core could not be verified stopped)");
            }
        }

        var protector = options.Protector ?? (OperatingSystem.IsWindows()
            ? new DpapiSecretProtector()
            : new DevOnlyPassThroughProtector());
        _protector = protector;
        Pairings = new PairingService(protector);
        // Durable pairing store: pairings survive Core restarts (the
        // always-on contract). Hash-only on disk, like the audit log's
        // redaction rule — a usable token never touches the file.
        var pairingsPath = Path.Combine(options.DataDir, "pairings.json");
        if (File.Exists(pairingsPath))
        {
            try { Pairings.ImportJson(File.ReadAllText(pairingsPath)); }
            catch { /* a corrupt store is re-paired by the owner, never fatal */ }
        }
        Pairings.Changed += () =>
        {
            try { WriteStoreAtomic(pairingsPath, Pairings.ExportJson()); } catch { }
            // A completed exchange consumes the bootstrap code file.
            try { File.Delete(Path.Combine(options.DataDir, "pairing-code.txt")); } catch { }
        };
        // Device identity (Slice 1): the seed persists ONLY as a
        // protector-wrapped value, mirroring the pairing store — the
        // raw seed never touches disk. A missing/corrupt store mints a
        // fresh identity and persists it; that is a re-enrollment
        // event for the owner, never a startup failure.
        var identityPath = Path.Combine(options.DataDir, "device-identity.txt");
        _identityPath = identityPath;
        DeviceIdentity? restoredIdentity = null;
        var identityFileExisted = File.Exists(identityPath);
        if (identityFileExisted)
        {
            try { DeviceIdentity.TryImportProtectedSeed(protector, File.ReadAllText(identityPath), out restoredIdentity); }
            catch { restoredIdentity = null; }
        }
        Identity = restoredIdentity ?? new DeviceIdentity(protector);
        string? identityAuditAction = null;
        if (restoredIdentity is null)
        {
            if (identityFileExisted)
            {
                // The stored identity failed to import: PRESERVE it
                // byte-for-byte under a corrupt-* name instead of
                // overwriting it — a transient protector failure or a
                // half-written file must not silently destroy the
                // machine's root identity (D38 S1-WIN F3). The rotation
                // is audited below, once Audit exists.
                try
                {
                    var corruptPath = (identityPath.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                            ? identityPath.Substring(0, identityPath.Length - 4)
                            : identityPath) + ".corrupt-" +
                        DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
                    if (File.Exists(corruptPath))
                        corruptPath += "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                    File.Move(identityPath, corruptPath);
                }
                catch { /* preservation is best-effort; rotation proceeds */ }
                identityAuditAction = "identity_rotated_corrupt_store_preserved";
            }
            else
            {
                identityAuditAction = "identity_minted";
            }
            try { WriteStoreAtomic(identityPath, Identity.ExportProtectedSeed()); } catch { }
            // C20 wiring: an identity minted at THIS boot (no file
            // existed) is not yet a live identity in use — it is the
            // one case a recovery restore may replace (see the
            // live-identity gate on OwnerRecoveryService below).
            _identityMintedThisRun = identityAuditAction == "identity_minted";
        }
        // Enrollment roster + receipts: public keys only on disk.
        Enrollments = new EnrollmentService(options.Clock ?? new SystemClock());
        // U9: the SAS responder key is this host's own identity key —
        // Redeem computes the SAS binding both keys + the code.
        Enrollments.LocalPublicKeyProvider = () => Identity.PublicKey;
        var enrollmentsPath = Path.Combine(options.DataDir, "enrollment.json");
        if (File.Exists(enrollmentsPath))
        {
            try { Enrollments.ImportJson(File.ReadAllText(enrollmentsPath)); }
            catch { /* a corrupt roster is re-enrolled by the owner, never fatal */ }
        }
        Enrollments.Changed += () =>
        {
            try { WriteStoreAtomic(enrollmentsPath, Enrollments.ExportJson()); } catch { }
        };
        // Roster & groups (Slice 2): scopes/users/groups/grants store,
        // derived from the enrollment roster above. Same minimal
        // wiring as enrollment — restore roster.json + write-through
        // on Changed; no MCP tools, IPC, or UI surfaces in this slice.
        Roster = new RosterService(Enrollments);
        var rosterPath = Path.Combine(options.DataDir, "roster.json");
        if (File.Exists(rosterPath))
        {
            try { Roster.ImportJson(File.ReadAllText(rosterPath)); }
            catch { /* a corrupt roster is rebuilt by the admins, never fatal */ }
        }
        Roster.Changed += () =>
        {
            try { WriteStoreAtomic(rosterPath, Roster.ExportJson()); } catch { }
        };
        // TOTAL POLICY CONTROL gate (Block G): the enterprise
        // service is composed below (it needs only the roster), but
        // the session store above it in this constructor already
        // consults the gate for its Block G surfaces — so the gate
        // is a delegate over a reference filled in when Enterprise
        // is constructed (the TerminalService pattern above). Until
        // then, and whenever no bundle is loaded, CheckFeature's
        // own posture applies: not policy-gated.
        Services.EnterpriseService? enterpriseRef = null;
        Func<string, string, Acp.Shared.Enterprise.PolicyVerdict> featureGate =
            (scopeId, key) => enterpriseRef?.CheckFeature(scopeId, key)
                   ?? new Acp.Shared.Enterprise.PolicyVerdict(true, "no policy bundle loaded — feature not policy-gated");
        Func<string, string, bool> featureRequired =
            (scopeId, key) => enterpriseRef?.FeatureRequired(scopeId, key) ?? false;
        Action<string, string?, string> gServiceAudit =
            (kind, actor, detail) => enterpriseRef?.AppendServiceAudit(kind, actor, detail);
        // Human session model (Slice 3): sessions/participants/events/
        // chat/file jobs store, built over the roster + enrollments
        // above (consent gates and the offboarding hook read them).
        // Same minimal wiring — restore sessions.json + write-through
        // on Changed; no MCP tools, IPC, or UI surfaces in this slice.
        HumanSessions = new SessionService(Roster, Enrollments, featureGate, featureRequired);
        var sessionsPath = Path.Combine(options.DataDir, "sessions.json");
        if (File.Exists(sessionsPath))
        {
            try { HumanSessions.ImportJson(File.ReadAllText(sessionsPath)); }
            catch { /* a corrupt session store is rebuilt by use, never fatal */ }
        }
        // Restart reconciliation (D38 F11): a session that was live
        // when the previous Core died has nothing live behind it —
        // end it with the named reason instead of resurrecting a
        // phantom active session (and phantom recording) at boot.
        try { HumanSessions.ReconcileAfterRestart(); } catch { }
        HumanSessions.Changed += () =>
        {
            try { WriteStoreAtomic(sessionsPath, HumanSessions.ExportJson()); } catch { }
        };
        // W12 / DS-P5-F2: device revocation ends that device's live
        // sessions. Enrollment changes are the revocation signal —
        // on every change, sweep sessions whose host device is now
        // revoked (the sweep is a no-op when nothing was revoked).
        Enrollments.Changed += () =>
        {
            try
            {
                foreach (var device in Enrollments.List().Where(d => d.Revoked))
                    HumanSessions.EndSessionsForDevice(device.DeviceId);
            }
            catch { }
        };
        // Enterprise wiring (Block F): the Block E services live
        // here — policy load (fail-closed), the persisted chained
        // audit, directory sync over the live roster, break-glass,
        // and the mock-IdP leg. Loads its own stores from the data
        // dir; a refused policy is a named state, never fatal.
        Enterprise = new Services.EnterpriseService(options.DataDir, Roster, protector: protector);
        enterpriseRef = Enterprise;
        // W45 / DS round-9 Item 3: the Core advances the install-
        // root anchor marker on every anchored append (freshness
        // no longer depends on a launcher visit). The install root
        // is the pointer-signing custody domain — the Core already
        // writes the seed/pin there, as the install owner in the
        // console-host shape and as SYSTEM in the service shape.
        Enterprise.AnchorMarkerInstallRoot = options.InstallRoot;
        // Block R foundation wiring (RMM-03 + RMM-07): the customer
        // command key ring loads from customer-command-keys.json in
        // the data dir ([{keyId, publicKeyBase64, retiredUntilUtc}] —
        // PUBLIC keys only; the customer's private key never reaches
        // this endpoint). No file (or an unreadable one) leaves the
        // gate UNWIRED: shell/session/update paths keep their
        // pre-RMM-03 posture and CommandGateState names it. With a
        // ring loaded, those paths REQUIRE verified signed commands.
        CommandGate = LoadCommandGate(options.DataDir);
        // D38 F10: policy is DURABLE — admitted documents, revision
        // floors and group definitions persist under the data dir
        // and restore at boot; a restart no longer silently clears
        // signed policy back to registry defaults.
        ManagementPolicies = new Services.ManagementPolicyService(Enterprise.AuditLog, CommandGate,
            storePath: Path.Combine(options.DataDir, "management-policy.json"));
        if (Enterprise.Enforcer is { } loadedBundleEnforcer)
        {
            // RMM-07 (f) bridge: the loaded enterprise bundle is the
            // management engine's first real policy document.
            ManagementPolicies.AdmitLocalDocument(
                Shared.ManagementPolicy.EnterpriseBundleBridge.FromBundle(loadedBundleEnforcer.Bundle),
                "enterprise bundle bridge at policy load");
        }
        // RMM-02 wiring: PatchService owns the endpoint-signed
        // PatchRun journal (persisted under <dataDir>/patch-jobs/)
        // and runs the RMM-15 Import → ResumeAll pass at start with
        // policy from ManagementPolicies. Parked jobs are reported
        // through its state report, never auto-resolved.
        Patches = new Services.PatchService(options.DataDir, Enterprise.AuditLog, ManagementPolicies,
            CommandGate, Identity, _commandKeyRing);
        Patches.Start(Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""));
        // RMM-05 wiring: the vulnerability loop correlates the hub
        // inventory store + the RMM-02 catalogue/approvals above.
        // It creates remediation requests and verifies closures; it
        // holds no deployment authority of its own.
        Vulnerabilities = new Services.VulnerabilityService(Enterprise.AuditLog, ManagementPolicies,
            Patches, HubInventory);
        // W11 / R-22: pin the vulnerability-feed producer key when
        // the operator has provisioned one at
        // <DataDir>/vuln-feed-signing-key.pub (base64, 32-byte
        // Ed25519 public key). With a key pinned, feed imports
        // REFUSE unsigned or wrongly-signed feeds; without one the
        // shipped admin-import trust shape stands and provenance
        // states the feed is unsigned — the pin is the operator's
        // act, never something a feed can supply about itself. A
        // malformed key file refuses to pin (and audits why) rather
        // than pinning garbage that would refuse every feed.
        var feedKeyPath = Path.Combine(options.DataDir, "vuln-feed-signing-key.pub");
        if (File.Exists(feedKeyPath))
        {
            try
            {
                var feedKey = Convert.FromBase64String(File.ReadAllText(feedKeyPath).Trim());
                Vulnerabilities.Feeds.PinSigningKey(feedKey);
                Enterprise.AuditLog.Append("vuln_feed_signing_key_pinned", "SYSTEM",
                    $"feed imports now require an Ed25519 signature verifying against the pinned key at {feedKeyPath}", DateTimeOffset.UtcNow);
            }
            catch (Exception ex)
            {
                Enterprise.AuditLog.Append("vuln_feed_signing_key_refused", "SYSTEM",
                    $"key file {feedKeyPath} could not be pinned ({ex.GetType().Name}: {ex.Message}) — feed imports remain in the unpinned posture, stated in provenance", DateTimeOffset.UtcNow);
            }
        }
        // RMM-12 wiring: the work-item store + PSA bridge over the
        // same chained audit log and policy service. Session lookup
        // reads the existing session record (HumanSessions was
        // constructed above); no webhook transport is wired yet, so
        // bridge deliveries remain visibly pending/failed rather
        // than being sent anywhere.
        WorkItems = new Services.WorkItemService(Enterprise.AuditLog, ManagementPolicies,
            id => HumanSessions.GetSession(id),
            // W3 host wiring (2): the store's scopeLookup resolves
            // a device's enterprise scope from the hub inventory
            // record (the scope the device was inventoried under);
            // an uninventoried device resolves to null and its
            // alert items refuse BY NAME (BD-SHARED-RMM-3/F5)
            // rather than opening unscoped.
            scopeLookup: id => HubInventory.Get(id)?.ScopeId,
            // W3 host wiring (3): the bridge's send-time DNS
            // resolver -- the system resolver, injected so the
            // bridge re-validates resolved addresses at send
            // time (BD-SHARED-RMM-3/F3/F8 rebinding defense).
            bridgeResolver: host => System.Net.Dns.GetHostAddresses(host));
        // RMM-18 wiring: encryption enforcement over the shared
        // chained audit log + management policies; escrow keys are
        // protected by the same ISecretProtector as the identity
        // store. Facts resolve to this endpoint itself (single-
        // device Core); hub-side multi-device facts arrive with the
        // hub wiring remainder.
        EncryptionEnforcement = new Services.EncryptionEnforcementService(
            Enterprise.AuditLog, ManagementPolicies,
            new Services.BitLockerDriver(), protector,
            id => id == Identity.DeviceId
                ? Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "")
                : null);
        // ---- Block R closing integration wiring (2026-11-21) ----
        // Facts seam for hub-shaped services: this Core is single-device;
        // facts resolve for the local device by id and, for hub-side
        // services that evaluate per-device policy, for any id as
        // scope-less facts (policy defaults then apply honestly).
        Func<string, Shared.ManagementPolicy.IDeviceFacts?> anyFacts =
            id => Shared.ManagementPolicy.StaticDeviceFacts.Of(id, "");
        Func<string, Shared.ManagementPolicy.IDeviceFacts?> selfFacts =
            id => id == Identity.DeviceId ? Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "") : null;
        var policyEngine = ManagementPolicies.Engine;
        AlertCentre = new Shared.Monitoring.HealthAlertCentre(Enterprise.AuditLog, new Shared.Enterprise.AlertCenter());
        HubHealth = new Shared.Monitoring.HubHealthIngest(AlertCentre, TimeSpan.FromMinutes(15));
        // RMM-04 hub remainders: persist inventory + unmanaged register
        // on Changed (hub persistence shape = the stores' own verified
        // ExportJson, written atomically like every other store here);
        // the register's managed-id predicate reads the enrollment
        // store, and enrollment consults the register before enrolling.
        var hubInventoryPath = Path.Combine(options.DataDir, "hub-inventory.json");
        if (File.Exists(hubInventoryPath))
        {
            try { HubInventory.ImportJson(File.ReadAllText(hubInventoryPath)); } catch { }
        }
        HubInventory.Changed += () =>
        {
            try { WriteStoreAtomic(hubInventoryPath, HubInventory.ExportJson()); } catch { }
        };
        UnmanagedRegister = new Shared.Inventory.UnmanagedAssetRegister(
            policyCheck: key => policyEngine.IsEnabled(
                Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""), key),
            isManagedDeviceId: id => Enrollments.List().Any(d => !d.Revoked &&
                string.Equals(d.DeviceId, id, StringComparison.OrdinalIgnoreCase)));
        var unmanagedPath = Path.Combine(options.DataDir, "unmanaged-assets.json");
        if (File.Exists(unmanagedPath))
        {
            try { UnmanagedRegister.ImportJson(File.ReadAllText(unmanagedPath)); } catch { }
        }
        UnmanagedRegister.Changed += () =>
        {
            try { WriteStoreAtomic(unmanagedPath, UnmanagedRegister.ExportJson()); } catch { }
        };
        Enrollments.IsUnmanagedAssetId = id => UnmanagedRegister.Get(id) is not null;
        HubInventorySvc = new Services.HubInventoryService(HubInventory,
            new Shared.Inventory.WarrantyService(new Shared.Inventory.HttpWarrantyLookup()),
            audit: null); // its IAuditLog is the Shared audit shape; the chained enterprise log does not implement it — named, not forced
        // RMM-06 (W11 / R-15): REAL host wiring replaces the former
        // in-memory + fake-capture stub. Per-target stores over
        // DirectoryBackupStorage at each policy target's locator,
        // each sealed at rest under its own DPAPI-wrapped key file
        // (BackupAtRest.LoadOrCreateKeyFile, key files in the Core
        // data dir — never at the target), catalogues persisted in
        // the data dir, and the real FileBackupCaptureSource (live
        // file reads, honestly not VSS-consistent; image jobs
        // refuse by name). The wiring report is audited: a target
        // that cannot be constructed refuses BY NAME there, and
        // jobs naming it refuse by name in BackupService.
        var (backupService, backupWiring) = Services.BackupHostWiring.Build(
            Enterprise.AuditLog, policyEngine, anyFacts,
            Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""),
            options.DataDir, protector, CommandGate);
        Backups = backupService;
        Enterprise.AuditLog.Append("backup_host_wiring", "SYSTEM", backupWiring.Summary, DateTimeOffset.UtcNow);
        // RMM-08: remediation with the production executor
        // (BD-WIN-CORE-3/F7): service/process/clear_path steps are
        // real OS acts; run_script/uninstall/rerun_patch still fail
        // BY NAME until their own host surfaces are wired. No signer
        // is wired (no customer signing key on this host).
        var remediationExecutor = new Services.WindowsRemediationStepExecutor();
        Remediation = new Services.RemediationService(Enterprise.AuditLog, policyEngine, anyFacts,
            null, CommandGate, remediationExecutor);
        // RMM-09: compliance over hub inventory + patches + vulns.
        // W37: pack keyed anchoring composes the SAME runtime
        // pointer-signing custody (install-root key) the Updates
        // composition below builds — a second file-backed instance
        // over the same key dir; EnsureKeyForInstall is idempotent,
        // so the later pointer composition is unaffected. A refused
        // custody is passed through so pack compiles refuse BY NAME
        // rather than silently fall back to the unkeyed anchor.
        Shared.Update.PointerSigningCustody? packSigning = null;
        if (options.InstallRoot is not null)
        {
            var packCustody = new Shared.Update.PointerSigningCustody(options.InstallRoot, options.DataDir);
            if (packCustody.CustodyRefusal is not null)
            {
                packSigning = packCustody;
                PackSigningStatus = packCustody.CustodyRefusal;
            }
            else
            {
                try
                {
                    packCustody.EnsureKeyForInstall();
                    packSigning = packCustody;
                    PackSigningStatus = $"pack signing: compliance packs are key-anchored under the runtime pointer-signing key, private half custodied in the install root '{options.InstallRoot}' (outside the data dir), public pin fingerprint {packCustody.Fingerprint}; rotation at each production-signed update apply archives the outgoing pin so pack signatures stay verifiable (W37)";
                }
                catch (Exception ex)
                {
                    PackSigningStatus = $"pack signing REFUSED by name ({ex.GetType().Name}: {ex.Message}) — packs remain in the LEGACY-UNKEYED-PACK posture, named, until custody is repaired (W37)";
                }
            }
        }
        else
        {
            PackSigningStatus = "pack signing NOT COMPOSED: no install root supplied to this composition — packs remain in the named LEGACY-UNKEYED-PACK posture (W37)";
        }
        Compliance = new Services.ComplianceService(Enterprise.AuditLog, ManagementPolicies,
            HubInventory, Patches, Vulnerabilities, packSigning: packSigning,
            // W47 (c): the pack-compile append + persist + marker
            // advance takes the ENTERPRISE chain's own gate and
            // verified persist — the same gated, verified operation
            // as the pointer path's appends, totally ordered with
            // them (round-10 Item 2).
            chainGate: Enterprise.ChainGate,
            persistChainVerified: Enterprise.PersistChainVerified);
        // Lane A hub persistence (item 1): RMM-05 exposures + feed,
        // RMM-09 treatments, RMM-12 work items — the RMM-04
        // write-through pattern with integrity envelopes and
        // corrupt-file preservation (RestoreHubStore).
        var exposuresPath = Path.Combine(options.DataDir, "hub-exposures.json");
        RestoreHubStore(exposuresPath, Vulnerabilities.Exposures.ImportJson, "acp-exposures-v1");
        Vulnerabilities.Exposures.Changed += () =>
        {
            try { WriteStoreAtomic(exposuresPath, Vulnerabilities.Exposures.ExportJson()); } catch { }
        };
        var vulnFeedPath = Path.Combine(options.DataDir, "hub-vuln-feed.json");
        RestoreHubStore(vulnFeedPath, t => Vulnerabilities.Feeds.ImportJson(t) ? 1 : 0, "acp-vuln-feed-v1");
        Vulnerabilities.Feeds.Changed += () =>
        {
            try { WriteStoreAtomic(vulnFeedPath, Vulnerabilities.Feeds.ExportJson()); } catch { }
        };
        var treatmentsPath = Path.Combine(options.DataDir, "hub-compliance-treatments.json");
        RestoreHubStore(treatmentsPath, Compliance.Treatments.ImportJson, "acp-compliance-treatments-v1");
        Compliance.Treatments.Changed += () =>
        {
            try { WriteStoreAtomic(treatmentsPath, Compliance.Treatments.ExportJson()); } catch { }
        };
        var workItemsPath = Path.Combine(options.DataDir, "hub-work-items.json");
        RestoreHubStore(workItemsPath, WorkItems.Store.ImportJson, "acp-work-items-v1");
        WorkItems.Store.Changed += () =>
        {
            try { WriteStoreAtomic(workItemsPath, WorkItems.Store.ExportJson()); } catch { }
        };
        // Lane A: RMM-16 hub package repository (constructed here so
        // its persistence lives with the other hub stores; the
        // deployment service consumes this same instance when the
        // host wires it).
        HubPackageVault = new Shared.Deployment.PackageSecretVault(protector);
        HubPackages = new Shared.Deployment.PackageRepository(HubPackageVault);
        var hubPackagesPath = Path.Combine(options.DataDir, "hub-packages.json");
        RestoreHubStore(hubPackagesPath, HubPackages.ImportJson, "acp-package-repository-v1");
        HubPackages.Changed += () =>
        {
            try { WriteStoreAtomic(hubPackagesPath, HubPackages.ExportJson()); } catch { }
        };
        // W5 host wiring (bd-shared-plat-1/F4 remainder): the
        // RMM-16 deployment service is composed over the repository
        // + vault above, the production remediation executor and
        // the command gate (no signer on this host — deployments
        // that require hub-signed envelopes refuse by name), with
        // the PRODUCTION verify_install probe: hub inventory for
        // the target device, corroborated locally by the OS
        // uninstall-registry read + service query, fail-closed
        // (unobservable ⇒ verify_install fails ⇒ PartialFailure,
        // never a claimed verification).
        SoftwareDeployments = new Services.SoftwareDeploymentService(Enterprise.AuditLog, policyEngine, anyFacts,
            signer: null, gate: CommandGate, repository: HubPackages, vault: HubPackageVault,
            executor: remediationExecutor);
        var installedVersionProbe = new Services.ProductionInstalledVersionProbe(
            deviceId => HubInventory.Get(deviceId), Identity.DeviceId);
        SoftwareDeployments.InstalledVersionProbe = installedVersionProbe.Observe;
        // RMM-10: background tools over the recording executor —
        // HONEST STUB: no OS executor is wired; the recording shape
        // executes nothing on the host.
        var bgExecutor = new Shared.BackgroundTools.RecordingBackgroundExecutor();
        BackgroundTools = new Shared.BackgroundTools.BackgroundToolsService(Enterprise.AuditLog, policyEngine,
            id => Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""),
            bgExecutor, new Shared.BackgroundTools.ExecutorKitByteStore(bgExecutor), CommandGate);
        // RMM-11: network discovery over the fake probe transport —
        // HONEST STUB: no live probing on this host. The hub seams are
        // real: isManagedDeviceId via the register above, and
        // SetKnownManagedMacs is callable by the hub duty loop.
        NetworkDiscovery = new Services.NetworkDiscoveryService(Identity.DeviceId, "",
            Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""), policyEngine,
            new Shared.NetworkDiscovery.ProductionProbeTransport(), new Shared.NetworkDiscovery.SiteCensus(),
            UnmanagedRegister, Enterprise.AuditLog, AlertCentre);
        // RMM-01 monitor + hub duty loop sources (item 2): warranty +
        // serial-conflict alerts feed from RMM-04's hub seams.
        Monitor = new Services.EndpointMonitorService(Identity.DeviceId,
            Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""), policyEngine,
            Services.RuntimeHealthCollector.Create(), AlertCentre, Enterprise.AuditLog,
            CommandGate, WorkItems, Remediation, null,
            warrantySource: now => HubInventorySvc.CollectWarrantyAlerts(now),
            serialConflictSource: now => HubInventory.CollectSerialConflictAlerts(now));
        // RMM-13: reporting over hub inventory + health ingest +
        // patches + backup facts + vulns. The HTTP listener is NOT
        // wired in this pass (named remainder in the integration log);
        // the service + its gated API dispatcher are.
        Reporting = new Services.ReportingService(Enterprise.AuditLog, ManagementPolicies,
            HubInventory, Identity, HubHealth, Patches, Backups, Vulnerabilities);
        // Lane A (item 6): the RMM-13 HTTP listener exists ONLY as a
        // front door to the dispatcher's existing authenticated
        // surface, and starts only when TOTAL POLICY CONTROL enables
        // rmm.reporting.http.enabled for this device (default off —
        // a stock hub grows no new network surface).
        // BD-WIN-CORE-3/F6: the listener now carries the gate itself
        // (Start + per-request), not just this call-site check.
        ReportingHttp = new Services.ReportingHttpListener(Reporting,
            facts: Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""),
            httpEnabled: () => policyEngine.IsEnabled(
                Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""),
                Services.ReportingHttpListener.PolicyKey));
        try { ReportingHttp.Start(); }
        catch { /* a listener that cannot bind stays down; the service + dispatcher remain available in-process */ }
        // RMM-20: runbooks over the same honest host executor + the
        // host-wiring check evaluator; automation library starts empty.
        Runbooks = new Services.RunbookService(Enterprise.AuditLog, policyEngine, anyFacts,
            null, CommandGate, remediationExecutor,
            // W3 host wiring (1): the PRODUCTION check evaluator
            // (BD-SHARED-RMM-3/F2) -- real local probes for the
            // five closed check kinds, failing BY NAME wherever a
            // fact cannot be observed. It replaces the
            // HostWiringRunbookCheckEvaluator stub, which failed
            // every check as "host wiring pending".
            new Shared.Runbooks.LocalRunbookCheckEvaluator(),
            () => new Shared.Remediation.AutomationLibrary("core", 0, Array.Empty<Shared.Remediation.AutomationDefinition>()),
            // BD-WIN-CORE-4/F6: unnamed-step approver/attester
            // authority is the roster's approver-principal registry
            // (snapshot at construction, the AppControl precedent) —
            // never "any second string".
            authorisedApproverIds: Roster.ApproverPrincipalIds(),
            authorisedAttesterIds: Roster.ApproverPrincipalIds());
        // RMM-28: health scoring with adapters over the real stores.
        // Lane A (item 3): provision the hub signing key BEFORE the
        // health-scoring store is built, so FL-28a runs keyed from
        // the first snapshot. Provisioning is generate-or-load,
        // sealed at rest, audited; on a host where it cannot run
        // the store stays unkeyed (hash+integrity imports only).
        HubSigningKeys = new Services.HubSigningKeyProvisioning(options.DataDir, protector, Enterprise.AuditLog);
        try { HubSigningKeys.ProvisionOrLoad(); } catch { /* unkeyed posture stands, named in HubSigningKeys.State */ }
        HealthScoring = new Services.HealthScoringService(Enterprise.AuditLog, policyEngine, anyFacts,
            new Services.HubMonitoringFactsSource(HubHealth, AlertCentre),
            new Services.ExposureStoreFactsSource(Vulnerabilities.Exposures,
                now => Vulnerabilities.Feeds.CurrentProvenance(now, 30)),
            Backups,
            new Services.DelegatePostureFactsSource(_ => null),
            new Services.InventoryStoreFactsSource(HubInventory),
            signingKey: HubSigningKeys.CurrentKey,
            previousSigningKey: HubSigningKeys.PreviousKey);
        // RMM-27: anomaly detection into the monitor cycle (Observe is
        // invoked from RunMonitorDutyCycle below).
        AnomalyDetection = new Services.AnomalyDetectionService(Enterprise.AuditLog, ManagementPolicies,
            AlertCentre, anyFacts);
        // RMM-17 (bd-win-core-3/F7 remainder, W9 closure):
        // EndpointSecurityService is now COMPOSED on this host with
        // real Windows bindings (EndpointSecurityBindings.cs): a
        // FileSystemWatcher activity source over the owner's
        // document roots + the data dir, a Defender-posture AV
        // source, and netsh isolation actuation. The isolation plan
        // exempts exactly ACP's own channels as configured here —
        // the hub endpoint (when one is configured) and this Core's
        // own loopback port — so an isolation can never cut the
        // management lifeline it is released through. Cycles run
        // from RunMonitorDutyCycle.
        var isolationExemptions = new List<Shared.EndpointSecurity.AcpChannelExemption>();
        if (!string.IsNullOrWhiteSpace(options.HubServerUrl) &&
            Uri.TryCreate(options.HubServerUrl, UriKind.Absolute, out var hubUri) && !string.IsNullOrWhiteSpace(hubUri.Host))
            isolationExemptions.Add(new Shared.EndpointSecurity.AcpChannelExemption(
                Shared.EndpointSecurity.ExemptionKinds.Hub, hubUri.Host, hubUri.Port > 0 ? hubUri.Port : 8443));
        isolationExemptions.Add(new Shared.EndpointSecurity.AcpChannelExemption(
            Shared.EndpointSecurity.ExemptionKinds.LanRung, "127.0.0.1", options.Port));
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        EndpointSecurity = new Services.EndpointSecurityService(Identity.DeviceId,
            Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""), policyEngine,
            new Shared.EndpointSecurity.RansomwareDetector(),
            new Services.FileSystemActivitySource(new[]
            {
                options.DataDir,
                Path.Combine(userProfile, "Documents"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Downloads"),
            }),
            new Shared.EndpointSecurity.EndpointIsolationManager(Identity.DeviceId,
                new Services.WindowsEndpointNetworkControl(), Enterprise.AuditLog),
            new Shared.EndpointSecurity.IsolationPlan(isolationExemptions),
            new Services.WindowsAvStatusSource(), AlertCentre, Enterprise.AuditLog, CommandGate);
        // RMM-19: baseline drift over the unavailable observed-state
        // provider — HONEST STUB: cycles report indeterminate by name.
        BaselineDrift = new Services.BaselineDriftService(Enterprise.AuditLog, ManagementPolicies,
            AlertCentre, CommandGate, new Shared.Baselines.UnavailableObservedStateProvider(),
            anyFacts, remediation: Remediation);
        // RMM-26 / RMM-23 / RMM-25 / RMM-30 / RMM-31 / RMM-32.
        SoftwareMetering = new Services.SoftwareMeteringService(Enterprise.AuditLog, ManagementPolicies, HubInventory);
        // W3 host wiring (4): HubPersistence write-through for the
        // three W2-B stores whose export/import existed but had no
        // host persistence -- RemediationLoopGuard (its history IS
        // a safety limit: a restart must not reset cooldowns or
        // the global storm cap), ScheduledReportRunner (a restart
        // must not re-fire every due report or drop retries) and
        // LicenceReportStore (licence history). Same pattern as
        // the Lane A hub stores above: restore at start through
        // RestoreHubStore (corrupt files are preserved, never
        // silently dropped), write through on Changed.
        var loopGuardPath = Path.Combine(options.DataDir, "hub-remediation-loop-guard.json");
        if (File.Exists(loopGuardPath))
        {
            // RestoreHubStore preserves a corrupt file by name
            // instead of dropping it; a failed restore seeds the
            // guard fail-closed (below), never a clean slate.
            if (RestoreHubStore(loopGuardPath, t => Remediation.LoopGuard.ImportJson(t) ? 1 : 0,
                    "acp-remediation-loop-guard-v1") == 0)
                Remediation.LoopGuard.SeedRestoredEmpty(DateTimeOffset.UtcNow);
        }
        else Remediation.LoopGuard.SeedRestoredEmpty(DateTimeOffset.UtcNow);
        Remediation.LoopGuard.Changed += () =>
        {
            try { WriteStoreAtomic(loopGuardPath, Remediation.LoopGuard.ExportJson()); } catch { }
        };
        var scheduledReportsPath = Path.Combine(options.DataDir, "hub-scheduled-reports-state.json");
        RestoreHubStore(scheduledReportsPath, t => Reporting.Scheduler.ImportStateJson(t) ? 1 : 0, "acp-scheduled-reports-state-v1");
        Reporting.Scheduler.Changed += () =>
        {
            try { WriteStoreAtomic(scheduledReportsPath, Reporting.Scheduler.ExportStateJson()); } catch { }
        };
        var licenceReportsPath = Path.Combine(options.DataDir, "hub-licence-reports.json");
        RestoreHubStore(licenceReportsPath, SoftwareMetering.ImportLicenceReportsJson, "acp-licence-reports-v1");
        SoftwareMetering.LicenceReportsChanged += () =>
        {
            try { WriteStoreAtomic(licenceReportsPath, SoftwareMetering.ExportLicenceReportsJson()); } catch { }
        };
        // VendorPasses is composed below, after SiteDocumentation:
        // its production credential vault is the site vault
        // (BD-SHARED-PLAT-3/F3).
        BrowserPolicy = new Services.BrowserPolicyService(Enterprise.AuditLog, policyEngine,
            new Shared.BrowserPolicy.UnavailableBrowserPolicyApplier(), anyFacts);
        AppControl = new Services.AppControlService(Enterprise.AuditLog, policyEngine,
            new Services.AppLockerPolicyWriter(Path.Combine(options.DataDir, "applocker")),
            new Shared.ApplicationControl.HealthAlertCentreAppBlockSink(AlertCentre),
            WorkItems.Store, anyFacts,
            approverPrincipalSource: () => Roster.ApproverPrincipalIds());
        PeripheralControl = new Services.PeripheralControlService(Enterprise.AuditLog, policyEngine,
            new Services.DeviceControlPolicyWriter(),
            new Shared.PeripheralControl.HealthAlertCentrePeripheralSink(AlertCentre),
            WorkItems.Store, anyFacts);
        MdmSubset = new Services.MdmSubsetService(Enterprise.AuditLog, policyEngine,
            // MDM requires a gate object; with no customer key configured
            // the gate over an EMPTY ring verifies nothing — fail-closed
            // by construction, never implied coverage.
            CommandGate ?? new Shared.Security.SignedCommandGate(
                new Shared.Security.SignedCommandVerifier(new Shared.Security.CustomerCommandKeyRing()),
                Enterprise.AuditLog),
            new Shared.MdmSubset.UnavailableMdmActionExecutor(), anyFacts);
        // bd-shared-plat-2/F8: persist the MDM locate limiter so a
        // Core restart cannot reset the anti-tracking 24h cap.
        {
            var mdmLocatePath = Path.Combine(options.DataDir, "mdm-locate-limiter.json");
            try { if (File.Exists(mdmLocatePath)) MdmSubset.ImportLocateLimiterJson(File.ReadAllText(mdmLocatePath), DateTimeOffset.UtcNow); } catch { }
            MdmSubset.LocateLimiterChanged += () =>
            { try { WriteStoreAtomic(mdmLocatePath, MdmSubset.ExportLocateLimiterJson()); } catch { } };
        }
        Dlp = new Services.DlpService(Enterprise.AuditLog, policyEngine,
            new Shared.Dlp.HealthAlertCentreDlpSink(AlertCentre),
            new Services.UnavailableDlpEgressApplier(), anyFacts);
        // RMM-24: directory enrollment over the FAKE connector —
        // HONEST STUB: no real directory is wired; sync reads the
        // fake's empty snapshot. Mobile operator over the alert centre.
        DirectoryEnrollment = new Services.DirectoryEnrollmentService(Enrollments, Roster,
            Enterprise.AuditLog, policyEngine, new Shared.DirectoryEnrollment.FakeDirectoryConnector(),
            new Services.RosterOffboardingInitiator(Roster, _ => null));
        MobileOperator = new Services.MobileOperatorService(Enrollments, Roster, Enterprise.AuditLog,
            policyEngine, "", id => AlertCentre.Get(id));
        // W5 wiring (bd-shared-plat-2/F12 remainder): the three
        // mobile stores are persisted — restore at startup, write
        // through on every change (the mdm-locate pattern). Files
        // carry the stores' own HubPersistence integrity envelopes.
        {
            var mobileClientsPath = Path.Combine(options.DataDir, "mobile-clients.json");
            RestoreHubStore(mobileClientsPath, MobileOperator.Clients.ImportJson, "acp-mobile-clients-v1");
            MobileOperator.Clients.Changed += () =>
            { try { WriteStoreAtomic(mobileClientsPath, MobileOperator.Clients.ExportJson()); } catch { } };
            var mobileApprovalsPath = Path.Combine(options.DataDir, "mobile-approvals.json");
            RestoreHubStore(mobileApprovalsPath, MobileOperator.Approvals.ImportJson, "acp-mobile-approvals-v1");
            MobileOperator.Approvals.Changed += () =>
            { try { WriteStoreAtomic(mobileApprovalsPath, MobileOperator.Approvals.ExportJson()); } catch { } };
            var mobileNotificationsPath = Path.Combine(options.DataDir, "mobile-notifications.json");
            RestoreHubStore(mobileNotificationsPath, MobileOperator.Notifications.ImportJson, "acp-mobile-notifications-v1");
            MobileOperator.Notifications.Changed += () =>
            { try { WriteStoreAtomic(mobileNotificationsPath, MobileOperator.Notifications.ExportJson()); } catch { } };
        }
        // RMM-21: site documentation (reveal gate unwired = reveals
        // refuse by name, per the service's own contract).
        SiteDocumentation = new Shared.SiteDocs.SiteDocumentationService(protector, Enterprise.AuditLog,
            Roster, policyEngine, anyFacts);
        // RMM-23 vendor passes, composed over the site vault
        // (BD-SHARED-PLAT-3/F3+F6+F7): the credential vault adapter
        // is backed by SiteDocumentationService (its injection seam
        // audits + binding-checks every resolve; a deleted site
        // credential stops resolving); the operator authorizer is
        // the roster (live human scope admin); the pass store's
        // exports are sealed with the host protector and persisted
        // write-through. The session-layer SINK is not wired: no
        // production ISessionCredentialSink exists on this host yet,
        // so the injector stays null and credential-bearing passes
        // refuse at issue — fail closed, named here, never faked.
        VendorPasses = new Services.VendorPassService(Enterprise.AuditLog, policyEngine, anyFacts,
            injector: null, teardown: null,
            operatorAuthorizer: (scopeId, userId) =>
            {
                var user = Roster.GetUser(scopeId, userId);
                return user is not null && !user.Suspended && user.Kind == "human" &&
                       Roster.IsScopeAdmin(scopeId, userId);
            },
            storeProtector: protector);
        {
            var vendorPassesPath = Path.Combine(options.DataDir, "vendor-passes.json");
            try
            {
                if (File.Exists(vendorPassesPath))
                    VendorPasses.Store.ImportJson(File.ReadAllText(vendorPassesPath));
            }
            catch { /* a sealed export that no longer unseals restores nothing — fail closed */ }
            VendorPasses.Store.Changed += () =>
            { try { WriteStoreAtomic(vendorPassesPath, VendorPasses.Store.ExportJson()); } catch { } };
        }
        // RMM-29: provisioning over the fake capture source +
        // unavailable imaging executor — HONEST STUBS, named in log.
        Provisioning = new Services.ProvisioningService(Enterprise.AuditLog, policyEngine, selfFacts,
            null, CommandGate, protector, new Shared.Provisioning.FakeProfileCaptureSource(),
            new Services.DismImagingExecutor());
        // RMM-22 / RMM-11-ext: camera share + viewing, hub-side
        // registration over the recording/stream sinks (no live RTSP
        // engine on this host — sinks record/refuse by shape).
        CameraShares = new Shared.CameraShare.CameraShareService(Roster, Enrollments, policyEngine,
            Enterprise.AuditLog, new Shared.CameraShare.RecordingCameraShareSink());
        CameraViewing = new Shared.NetworkDiscovery.CameraViewService(UnmanagedRegister, Roster,
            policyEngine, Enterprise.AuditLog, new Shared.NetworkDiscovery.RecordingCameraStreamSink(),
            snapshotBaseDir: Path.Combine(options.DataDir, "camera-snapshots"));
        // Block G services (2026-11-20): wake registry (G-01),
        // standalone transfers (G-04), local second factor (G-06),
        // session tunnels (G-08) — each restored from its own store
        // in the data dir with write-through on Changed, each gated
        // by Enterprise.CheckFeature (TOTAL POLICY CONTROL). The
        // second factor's secrets live ONLY in its store, sealed by
        // the same protector as the identity/pairing stores.
        Wake = new WakeService(Roster, Enrollments, new UdpWakeSender(), featureGate, gServiceAudit);
        var wakePath = Path.Combine(options.DataDir, "wake-targets.json");
        if (File.Exists(wakePath))
        {
            try { Wake.ImportJson(File.ReadAllText(wakePath)); } catch { }
        }
        Wake.Changed += () =>
        {
            try { WriteStoreAtomic(wakePath, Wake.ExportJson()); } catch { }
        };
        StandaloneTransfers = new StandaloneTransferService(Roster, Enrollments, featureGate, gServiceAudit);
        var standalonePath = Path.Combine(options.DataDir, "standalone-transfers.json");
        if (File.Exists(standalonePath))
        {
            try { StandaloneTransfers.ImportJson(File.ReadAllText(standalonePath)); } catch { }
        }
        StandaloneTransfers.Changed += () =>
        {
            try { WriteStoreAtomic(standalonePath, StandaloneTransfers.ExportJson()); } catch { }
        };
        SecondFactors = new SecondFactorService(Roster, protector, featureGate, gServiceAudit);
        var secondFactorPath = Path.Combine(options.DataDir, "second-factors.json");
        if (File.Exists(secondFactorPath))
        {
            try { SecondFactors.ImportJson(File.ReadAllText(secondFactorPath)); } catch { }
        }
        SecondFactors.Changed += () =>
        {
            try { WriteStoreAtomic(secondFactorPath, SecondFactors.ExportJson()); } catch { }
        };
        SessionTunnels = new SessionTunnelService(HumanSessions, Roster, featureGate, gServiceAudit,
            allowedTargets: LoadTunnelAllowlist(options.DataDir));
        var tunnelsPath = Path.Combine(options.DataDir, "session-tunnels.json");
        if (File.Exists(tunnelsPath))
        {
            try { SessionTunnels.ImportJson(File.ReadAllText(tunnelsPath)); } catch { }
        }
        SessionTunnels.Changed += () =>
        {
            try { WriteStoreAtomic(tunnelsPath, SessionTunnels.ExportJson()); } catch { }
        };
        // Tunnel sweep: a session that ends or blocks takes its
        // tunnels with it (the per-act re-read in the service is
        // the gate; this is the eager form, queued off-thread for
        // the same lock-order reason as the offboarding sweep).
        HumanSessions.Changed += () =>
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    foreach (var t in SessionTunnels.ListOpen())
                    {
                        var s = HumanSessions.GetSession(t.SessionId);
                        if (s is null || s.State is not ("active" or "paused"))
                            SessionTunnels.CloseForSession(t.SessionId);
                    }
                }
                catch { /* the per-act re-read remains the gate */ }
            });
        };
        // Policy teardown at startup (Block H): if the bundle on
        // disk disables features whose effects somehow survived
        // restore (live calls, open tunnels, running jobs), the
        // sweep ends them before this Core serves anything. The
        // live path is the policy_reload host action below; this
        // is the same sweep at the only other moment policy loads.
        try { ApplyPolicyTeardown(); } catch { /* the per-act gates remain the floor */ }
        // Terminal channel (Block F): session-scoped, floor-gated,
        // ConPTY-backed on Windows. The AI capability delegate reads
        // the pairing store: an AI reaches a terminal only when a
        // live pairing under its own name carries the named
        // `terminal` scope (no preset includes it — default OFF, D9).
        TerminalService? terminalsRef = null;
        var terminalSink = new Services.ConPtyTerminalSink((id, line) => terminalsRef?.AppendOutput(id, line));
        terminalsRef = Terminals = new TerminalService(HumanSessions, Roster,
            aiTerminalCapability: (scopeId, userId) =>
            {
                var user = Roster.GetUser(scopeId, userId);
                if (user is null) return false;
                // BD-WIN-CORE-1 F2: the name match must be UNIQUE —
                // exactly one unrevoked pairing under the AI user's
                // display name may carry the terminal scope (the
                // BlockGActors.ResolveAiUser discipline). Two
                // same-named pairings make the attribution ambiguous
                // and refuse. (The service's delegate carries no
                // pairing id — Acp.Shared terminal surface — so a
                // unique-name binding is the strongest form this
                // wiring supports; named residual in the fix log.)
                var matches = Pairings.List().Where(p => !p.Revoked && p.Scopes.Contains(Scopes.Terminal) &&
                    string.Equals(p.AgentName, user.DisplayName, StringComparison.OrdinalIgnoreCase)).ToList();
                return matches.Count == 1;
            },
            sink: terminalSink);
        QuickAssist = new QuickAssistService();
        // BD-SHARED-TRANSPORT F5: a WebRTC code's device must be a
        // party to its session — this device (host of the sessions
        // it serves) or the session's host device.
        WebRtc = new WebRtcSignaling(Enrollments, HumanSessions,
            (session, deviceId) => string.Equals(session.HostDeviceId, deviceId, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Identity.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
        AiPack = new AiPackService(AiPackManifest.UiTars15_7B);
        AiPackHome = Path.Combine(options.DataDir, "aipack", AiPackManifest.UiTars15_7B.PackId);
        // Transport core (Block C parts 1+3 + Block F): the failover
        // engine walks the Slice 2 resolved sets over the Slice 3
        // session store. Registered rungs: `lan` (part 1), `hub`
        // (part 3 — membership read lazily from the hub node
        // registry below, which is composed later in this
        // constructor), `mesh` (part 3 — connects only behind a
        // verified D4 setup), and Block F's `ipv6` (direct global
        // IPv6), `ownpath` (ACP-generated WireGuard peer set, read
        // from ownpath-peers.json at connect time), and `tor`
        // (SOCKS via ACP's configured Tor proxy, tor.json). All six
        // automatic rungs (D32) are now registered; manual WebRTC
        // sits below the chain by design (WebRtc above).
        MeshSetup = new MeshSetupService(new TailscaleCliProbe(), new TailscaleHttpApi(), protector);
        Transports = new TransportSessionManager(Roster, HumanSessions,
            new ITransportRung[]
            {
                // BD-SHARED-TRANSPORT F1/F9: every rung carries the
                // enrollment service — sessions ride the mutually
                // authenticated AEAD channel, and a rung without
                // enrollments fails closed rather than falling
                // back to plaintext. Mesh additionally re-verifies
                // readiness at connect time (F9) via the setup
                // service's live re-probe.
                new LanRung(Enrollments),
                new HubRung(deviceId => HubNodes is not null && HubNodes.Get(deviceId) is { Deleted: false }, enrollments: Enrollments),
                new MeshRung(() => MeshSetup.State, enrollments: Enrollments, readinessRecheck: () => MeshSetup.ReverifyReadiness()),
                new Ipv6Rung(enrollments: Enrollments),
                new OwnPathRung(() => ReadOwnPathPeers(options.DataDir), Enrollments),
                new TorRung(() => ReadTorConfig(options.DataDir), Enrollments),
            }, Identity);
        // BD-SHARED-TRANSPORT F1: listeners carry THIS device's
        // identity — the host side of the v2 handshake signs with
        // it and refuses every session when it is absent.
        LanListener = new LanHostListener(Enrollments, Identity);
        HubListener = new LanHostListener(Enrollments, Identity);
        // Offboarding hook, wired (D38 F4 / D14): any roster mutation
        // (removal, suspension) sweeps the live human sessions so a
        // removed or suspended participant's session ends promptly —
        // not only when someone happens to attempt a transition. The
        // sweep is queued off-thread: Roster.Changed fires under the
        // roster's lock, and running the session store inline here
        // would invert the lock order against session acts that read
        // the roster.
        Roster.Changed += () =>
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    foreach (var s in HumanSessions.ListSessions())
                        if (s.State != "ended")
                            HumanSessions.EnforceOffboarding(s.Id);
                }
                catch { /* the sweep is a backstop; per-act checks remain the gate */ }
            });
        };
        Audit = new FileAuditLog(Path.Combine(options.DataDir, "audit", "audit.jsonl"));
        if (!protector.IsRealProtection)
        {
            // The seed's at-rest protection is only as strong as the
            // protector in force (D38 S1-WIN F6): the pass-through
            // protector is dev-only and trivially reversible, so its
            // use is NEVER silent — it is audited loudly at every boot
            // it protects the identity/pairing stores. (On a Windows
            // production host the default protector is DPAPI and the
            // self-check reports RED if this one is ever in force.)
            try
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                    "secret_protector_not_real_protection:" + protector.Name, "SYSTEM", null));
            }
            catch { }
        }
        if (identityAuditAction is not null)
        {
            // Identity mint/rotation reaches the audit log as soon as
            // the log exists (D38 S1-WIN F3/F8): the DeviceId only —
            // never seed material.
            try
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                    identityAuditAction + ":" + Identity.DeviceId, "SYSTEM", null));
            }
            catch { }
        }
        // W107 (W106-verified C5): a pairing whose stored
        // connection record was present-but-corrupt restored
        // FAIL-CLOSED (PairingService quarantine) — that restore is
        // audited here, as soon as the chain exists, naming the
        // pairing and the preserved original mode; every refused
        // arrival is then audited per-arrival by the choke point
        // (pairing_connection_refused). The owner repairs by
        // re-setting the path on the agent card.
        try
        {
            foreach (var p in Pairings.List().Where(p => p.ConnectionNeedsAttention))
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", p.Id, p.AgentName, null, null, null,
                    $"pairing_connection_corrupt_refused:stored connection setting for this pairing could not be read " +
                    $"(stored mode '{p.CorruptConnectionMode ?? "(none)"}'); the record is preserved unchanged and every " +
                    "connection path is refused until the owner sets the connection path again", "SYSTEM", null));
        }
        catch { }
        // U9: mirror SAS audit entries (unconfirmed at redeem,
        // confirmed / mismatch from the endpoint-local human act)
        // into the host audit log as soon as the log exists.
        Enrollments.SasAuditAppended += entry =>
        {
            try
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                    entry.Action + ":" + entry.DeviceId, "SYSTEM", null));
            }
            catch { }
        };
        Marker = new RunMarker(Path.Combine(options.DataDir, "run-marker.json"));

        LoadStartupGates();
        var runner = options.Runner ?? new SystemProcessRunner();
        var factChecks = options.FactChecks ?? new WindowsFactChecks(runner);
        // Per-boot IPC secret (C2): written to the ACL'd data dir where
        // only SYSTEM and the owner can read it; the session agent
        // presents it in its Hello before any state or tool traffic is
        // trusted from the pipe.
        var ipcToken = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        // W20 token channel (revises BD-WIN-CORE-1 F1's env-only
        // delivery, on the W19 diagnosis): the token reaches an agent
        // through TWO deliveries of the SAME per-boot secret —
        // (a) the launch environment block (WindowsAgentLauncher +
        // ACP_IPC_TOKEN) for Core-launched agents, unchanged; and
        // (b) a token FILE in this data dir, ACL'd to SYSTEM + the
        // console user only, for task-launched agents (the logon
        // task can never receive a Core env block — env-only delivery
        // deadlocked AgentConnected=false under the console-host +
        // logon-task shape). Publish ROTATES: the fresh token
        // atomically replaces any stale file (the pre-W20 code only
        // deleted the stale file — the rotation's first half). The
        // IPC server's OS-identity verification (console session +
        // console user + agent image) is untouched and remains the
        // primary gate; the token is one factor, from either source.
        // Clean shutdown deletes the file (StopAsync/DisposeAsync).
        IpcTokenFileStatus = Services.IpcTokenFileChannel.Publish(options.DataDir, ipcToken);
        try
        {
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                IpcTokenFileStatus, "SYSTEM", null));
        }
        catch { }
        // BD-SUPP-EVENTSUB F1/F2: the bus is wired with the LIVE
        // per-(pairing, scope) lookup and this host's device id.
        // The pre-fix line used the one-argument constructor, whose
        // null delegate the delivery rule treated as ALLOW — so in
        // production a pairing whose Observe had been removed kept
        // receiving events. The bus is fail-closed now: no delegate,
        // no delivery; here the delegate reads the pairing store at
        // every delivery, so revocation and scope state are current.
        AgentEvents = new Shared.Sessions.AgentEventBus(EventSubscriptions,
            (pairingId, scope) => Pairings.List().FirstOrDefault(p => p.Id == pairingId)?.Scopes.Contains(scope) == true,
            Identity.DeviceId);
        // C20 wiring: the owner-local recovery service. The
        // live-identity gate: a restore may land only when there is
        // no identity IN USE — the current identity was minted at
        // this boot (nothing existed on disk) AND no pairing, roster
        // scope, live enrollment, or live session of either kind
        // exists. The C20 service additionally refuses over non-empty
        // pairing/roster stores itself; this delegate covers the
        // identity leg with the host's fuller picture. Apply: persist
        // the rebuilt identity through the same protector seam +
        // atomic store write as boot, and swap the runtime identity.
        // (Services composed earlier that captured the pre-restore
        // identity OBJECT — the transport manager, the patch service
        // — rebind on the next Core start; the restore result detail
        // says so, and no session can exist yet in the gated state.)
        Recovery = new Services.OwnerRecoveryService(
            identity: () => Identity,
            protector: protector,
            pairings: Pairings,
            roster: Roster,
            audit: Audit,
            liveIdentityExists: () => !(_identityMintedThisRun
                && Pairings.List().Count == 0
                && Roster.ListScopes().Count == 0
                && Enrollments.List().All(d => d.Revoked)
                && Sessions.Current is null
                && HumanSessions.ListSessions().All(s => s.State == "ended")),
            applyIdentity: restored =>
            {
                WriteStoreAtomic(_identityPath, restored.ExportProtectedSeed());
                Identity = restored;
                _identityMintedThisRun = false;
            },
            presenceNote: note =>
            {
                State.LastNarration = "Recovery restore completed on this device";
                AgentEvents.Publish(Shared.Sessions.AgentEventKinds.Session, note, null);
            });
        // W25: the Core's asymmetric identity for the agent
        // channel (CoreIdentity / CoreIdentityChannel). Loaded
        // (or minted) BEFORE the IPC server so every HelloAck
        // this boot carries the identity signature; the status is
        // audited alongside the token-file status. The Agent pins
        // the public key from its install record and refuses a
        // pipe host — however good its HMAC — that cannot sign.
        var (coreIdentity, coreIdentityStatus) = Services.CoreIdentityChannel.LoadOrCreate(
            options.DataDir, protector, options.AgentExePath);
        CoreIdentityStatus = coreIdentityStatus;
        try
        {
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                coreIdentityStatus, "SYSTEM", null));
        }
        catch { }
        // W28: provision the install trust record — the Agent's
        // ONLY trust anchor from this wave on (InstallTrust).
        // Written from this Core's own identity + configured
        // paths, re-asserted every boot, audited by status.
        InstallTrustRecordStatus = Services.InstallTrustRecordChannel.Provision(
            options.DataDir, coreIdentity, options.AgentExePath, Environment.ProcessPath);
        try
        {
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                InstallTrustRecordStatus, "SYSTEM", null));
        }
        catch { }
        Ipc = new AgentIpcServer(State, ipcToken, expectedAgentImagePath: options.AgentExePath,
            coreIdentity: coreIdentity);
        Ipc.Events = AgentEvents;
        Ipc.LivePairingIdProvider = () => Sessions.Current?.PairingId;
        // U7 link-loss fail-safe (Core leg): an agent-channel drop
        // during a live session ends the session immediately — see
        // OnAgentLinkLost. The agent releases held input on its own
        // side of the same drop; this leg removes the session the
        // held input belonged to.
        Ipc.AgentConnectionDropped += OnAgentLinkLost;
        Ipc.AgentMessageReceived += msg =>
        {
            // Gate approvals arrive ONLY over this authenticated channel
            // from the laptop UI (C3) — never from a file a tool can edit.
            // The IPC server raises this event only for messages from
            // the token-authenticated agent, so by the time we are here
            // the sender IS the laptop UI.
            if (msg.Kind == IpcKinds.Hello)
            {
                // W20: the Hello payload names the token's delivery
                // source (env|file|none — metadata only, never the
                // token). The audit records which channel carried
                // this agent's copy of the per-boot secret.
                // W22 pin: the label is AGENT-ASSERTED — it is
                // coerced through IpcTokenFile.AuditLabel before it
                // touches the audit chain (a forged label records as
                // "unrecognized", never as raw payload text), and it
                // is consumed NOWHERE else: no gate, posture, or
                // authorisation reads it. The token's worth is
                // proven by the HMAC handshake, not by this label.
                var source = "none";
                try
                {
                    if (msg.ArgumentsJson is not null)
                    {
                        using var helloDoc = JsonDocument.Parse(msg.ArgumentsJson);
                        if (helloDoc.RootElement.TryGetProperty("tokenSource", out var ts) && ts.GetString() is { Length: > 0 } s)
                            source = Shared.Ipc.IpcTokenFile.AuditLabel(s);
                    }
                }
                catch { }
                try
                {
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                        $"ipc_source:{source}", "SYSTEM", null));
                }
                catch { }
            }
            if (msg.Kind == IpcKinds.Auth)
            {
                // U1: a freshly authenticated agent gets the current
                // clipboard policy immediately — its engine copy is
                // the second wall at the clipboard path and must not
                // stand at defaults longer than the handshake.
                _ = PushClipboardPolicySafelyAsync();
                // FR-120 (W73): same discipline for the takeover
                // fleet defaults — the agent applies them in memory
                // only where the device has not chosen.
                _ = PushTakeoverDefaultsSafelyAsync();
            }
            else if (msg.Kind == IpcKinds.TakeoverEvent)
                // FR-120 (W73): a takeover session-record fact from
                // the agent. The kind and actor are AGENT-REPORTED
                // labels, coerced through the closed FR-120
                // vocabularies before they touch the chain (a
                // foreign kind/actor records as "unrecognized",
                // never as raw payload text); the detail is
                // audit-escaped by the chain's own redaction. This
                // is a REPORT path only — nothing here can set a
                // mode, on either side of the pipe.
                RecordTakeoverEvent(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.GateApproval)
                TryApplyGateApproval(msg.ArgumentsJson);
            // Vault seeding/wipe arrive over the same authenticated
            // channel from the same laptop UI (the vault panel). There
            // is deliberately no tool, file, or HTTP path into these
            // either: the person typing at the laptop is the consent.
            else if (msg.Kind == IpcKinds.VaultSet)
                _ = ApplyVaultFromLaptopAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.VaultWipe)
                _ = ApplyVaultWipeFromLaptopAsync();
            // STOP engaged/cleared from the laptop UI: the audit log
            // records both edges (the block itself is applied by the
            // IPC server's own switch; the session end is the
            // supervisor's job, one place for every STOP source).
            else if (msg.Kind == IpcKinds.UserStop)
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "user_stop_engaged", "SYSTEM", null));
            else if (msg.Kind == IpcKinds.UserStopClear)
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "user_stop_cleared", "SYSTEM", null));
            // Companion-window state (M4, 2026-11-17): the window asks
            // for the host-state snapshot and renders only what it
            // contains; pairing revoke + code minting arrive over the
            // same laptop-UI-only channel (codes are minted on the
            // host, never remotely — C1). Each is audited.
            else if (msg.Kind == IpcKinds.HostStateRequest)
                _ = PushHostStateSafelyAsync();
            else if (msg.Kind == IpcKinds.PairingRevoke)
            {
                if (TryRevokePairingFromLaptop(msg.ArgumentsJson))
                    _ = PushHostStateSafelyAsync();
            }
            else if (msg.Kind == IpcKinds.PairingCreateCode)
                _ = PushPairingCodeSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.PairingAccess)
                _ = ApplyPairingAccessSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.PairingConnection)
                _ = ApplyPairingConnectionSafelyAsync(msg.ArgumentsJson);
            // Slice 2/3 live wiring (Block A, 2026-11-19): roster,
            // session, and enrollment acts from the host window. Same
            // channel discipline as everything above — authenticated
            // laptop UI only; each act is audited and answered with an
            // action_result plus a fresh host-state snapshot.
            else if (msg.Kind == IpcKinds.RosterAction)
                _ = ApplyRosterActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.RosterOffboardPreview)
                _ = PushOffboardBlastSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.SessionAction)
                _ = ApplySessionActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.EnrollmentMint)
                _ = PushEnrollmentCodeSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.EnrollmentRedeem)
                _ = ApplyEnrollmentRedeemSafelyAsync(msg.ArgumentsJson);
            // Transport core (Block C part 1): transport-layer session
            // starts / re-establishment, the LAN listener switch, and
            // local discovery — same laptop-UI-only channel.
            else if (msg.Kind == IpcKinds.TransportAction)
                _ = ApplyTransportActionSafelyAsync(msg.ArgumentsJson);
            // Hub component (Block C part 2): stand-up/join acts from
            // the host window, same channel discipline as above.
            else if (msg.Kind == IpcKinds.HubAction)
                _ = ApplyHubActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.HubMintJoin)
                _ = PushHubJoinTicketSafelyAsync(msg.ArgumentsJson);
            // Block F surfacing: enterprise wiring, session terminal,
            // quick assist, manual WebRTC, AI pack — same laptop-UI-
            // only channel discipline as every action above.
            else if (msg.Kind == IpcKinds.EnterpriseAction)
                _ = ApplyEnterpriseActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.TerminalAction)
                _ = ApplyTerminalActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.QuickAssistAction)
                _ = ApplyQuickAssistActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.WebRtcAction)
                _ = ApplyWebRtcActionSafelyAsync(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.AiPackAction)
                _ = ApplyAiPackActionSafelyAsync(msg.ArgumentsJson);
            // Tor provisioning (W19-C): the setup act's FIRST
            // production caller — same laptop-UI-only channel.
            else if (msg.Kind == IpcKinds.TorAction)
                _ = ApplyTorActionSafelyAsync(msg.ArgumentsJson);
            // Block H surfacing: the Block G services' host-window
            // acts (Services page) — same channel discipline.
            else if (msg.Kind == IpcKinds.BlockGAction)
                _ = ApplyBlockGActionSafelyAsync(msg.ArgumentsJson);
            // C20 recovery (2026-11-22): export/restore acts from the
            // host window — same laptop-UI-only channel discipline as
            // every act above; there is no other path into them.
            else if (msg.Kind == IpcKinds.RecoveryAction)
                _ = ApplyRecoveryActionSafelyAsync(msg.ArgumentsJson);
            // W9 Agent chat host surface (Addendum A): the owner
            // sends from the host window and reads the thread there.
            // Same laptop-UI-only channel; the Core appends to the
            // pairing's own thread only, counts the send as Sent in
            // the data-flow ledger, and audits metadata, never text.
            else if (msg.Kind == IpcKinds.ChatSend)
                ApplyChatSendFromLaptop(msg.ArgumentsJson);
            else if (msg.Kind == IpcKinds.ChatThreadRequest)
                _ = PushChatThreadSafelyAsync(msg.ArgumentsJson);
            // W120 / S13: the owner's answer on an order card —
            // the card is the gate for the order's exact bytes.
            else if (msg.Kind == IpcKinds.ChatOrderAnswer)
                ApplyChatOrderAnswerFromLaptop(msg.ArgumentsJson);
        };
        Lanes = new LaneSupervisor(options.Probe ?? new NetworkProbe(), options.Clock ?? new SystemClock(), () => Random.Shared.NextDouble());
        State.Lanes = Lanes;

        var fileScope = new FileScope(options.FileRoots.Count > 0
            ? options.FileRoots
            : new[] { Path.Combine(options.DataDir, "staging") });
        Directory.CreateDirectory(fileScope.Roots[0]);

        SelfCheck = new CoreSelfCheck(State, Audit, Pairings, factChecks, Ipc);
        Func<CancellationToken, Task<IReadOnlyList<Shared.State.SubsystemHealth>>> selfCheckFn =
            ct => SelfCheck.BuildAsync(ct);

        Tools.Register(new EndpointStateModule(State, selfCheckFn));
        Tools.Register(new SelfCheckModule(selfCheckFn));
        Tools.Register(new AgentVersionModule(State));
        Tools.Register(new SessionStatusModule(Sessions,
            () => SessionPicture.All(HumanSessions, Roster, DateTimeOffset.UtcNow),
            // U4: deferred — Mcp (and its budget counters) is built
            // later in this constructor; the closure reads it at
            // call time, when it exists.
            () => Sessions.Current is { } cur
                ? Mcp.Budgets.Snapshot(cur.Id, Sessions.IsPaused, Sessions.PauseReason)
                : null,
            // U5: deferred like the budget closure — Mcp (and its
            // flow ledger) is built later in this constructor. The
            // report is a pure derivation over the ledger records +
            // the audit tail; gaps surface inside it, never hidden.
            () => Mcp.Flows is { } flowLedger
                ? DataFlowReport.Build(flowLedger.Records(), Audit.ReadTail(5000))
                : null));
        Tools.Register(new SessionStartModule(Sessions, State, CommandGate));
        Tools.Register(new SessionStopModule(Sessions, State, Ipc));
        Tools.Register(new ShellExecSystemModule(runner, CommandGate));
        Tools.Register(new FileReadModule(fileScope));
        Tools.Register(new FileWriteModule(fileScope));
        Tools.Register(new FileListModule(fileScope));
        Tools.Register(new ProcessListModule());
        Tools.Register(new AuditLogReadModule(Audit));
        Tools.Register(new PairingAdminModule(Pairings, Sessions, OnPairingRevokedSessionEnd,
            pairingRevoked: id =>
            {
                AgentEvents.RevokePairing(id);
                // W9 chat parity: unpairing ends the thread (both
                // legs then refuse/empty for the dead pairing).
                try { Chat.EndThread(id); Orders.EndOrders(id); ChatSeen.EndSeen(id); } catch { }
                GateRequests.InvalidatePairing(id);
            }));
        // W9 chat parity (Addendum A): chat_read / chat_post on the
        // Core MCP surface, caller-bound to the calling pairing.
        Chat = new Shared.Sessions.AgentChatStore(Path.Combine(options.DataDir, "chat"));
        Orders = new Shared.Sessions.ChatOrderStore(Path.Combine(options.DataDir, "chat"));
        ChatSeen = new Shared.Sessions.ChatSeenStore(Path.Combine(options.DataDir, "chat"));
        var chatPost = new ChatPostModule(Chat, id => Pairings.List().Any(p => p.Id == id));
        chatPost.Posted += audit =>
        {
            AgentEvents.Publish(Shared.Sessions.AgentEventKinds.Session,
                $"chat_message_received: pairing={audit.PairingId} direction={audit.Direction} chars={audit.Chars}", audit.PairingId);
            // W120: an open thread re-renders live when the agent
            // posts — the push is dropped by the window unless
            // this pairing's thread is the open one.
            _ = PushChatThreadSafelyAsync(JsonSerializer.Serialize(new { pairingId = audit.PairingId }));
            // W122 / N22: the inbox index changes with the post —
            // refresh the snapshot so the lens shows the new
            // unread state without waiting for the next tick.
            _ = PushHostStateSafelyAsync();
        };
        var chatRead = new ChatReadModule(Chat, id => Pairings.List().Any(p => p.Id == id));
        chatRead.Read += (pairingId, cursor) => _chatAgentCursor[pairingId] = cursor;
        Tools.Register(chatRead);
        Tools.Register(chatPost);
        // W120 / S13: the structured order-proposal tool (§8).
        // Proposing lands a card in the caller's own thread and
        // executes nothing; the owner's card answer is the only
        // execution door (ApplyChatOrderAnswerFromLaptop).
        var chatOrder = new ChatOrderModule { Propose = ApplyChatOrderProposal };
        Tools.Register(chatOrder);
        Tools.Register(new ScreenshotModule(Ipc));
        Tools.Register(new SnapshotModule(Ipc));
        Tools.Register(new ClickModule(Ipc));
        Tools.Register(new TypeTextModule(Ipc));
        Tools.Register(new KeyPressModule(Ipc));

        // ---- Phase 1 full parity + Phase 2 wiring (expanded build) ----
        var registry = new WindowsRegistryProvider();
        var serviceProvider = new WindowsServiceProvider();
        var stagingRoot = fileScope.Roots[0];
        var restarter = new AgentRestarter(Ipc, Audit);

        // Self-update (W15 / DS-P9-F6, fail-closed): pinned product
        // key when the installer ships one beside the executable.
        // NO key file + NO explicit dev opt-in => the update surface
        // is composed over AbsentKeyUpdateVerifier with a named
        // fail-closed reason: stage/apply refuse, nothing runs on an
        // ephemeral or absent key in production. The dev-ephemeral
        // keypair survives ONLY behind the update posture's OWN
        // explicit dev opt-in (W19 / DS-B-17 split, decided by the
        // one canonical path DevEphemeralUpdateKeyOptIn:
        // CoreOptions.AllowDevEphemeralUpdateKey or
        // ACP_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1), labelled in the
        // status report and audited below. The IPC no-token
        // variable ACP_DEV_ALLOW_NO_TOKEN is NOT read here — it
        // belongs exclusively to IpcTrust.Decide in the Agent.
        var pinnedKeyPath = Path.Combine(AppContext.BaseDirectory, "update-key.pub");
        var hasPinnedKey = File.Exists(pinnedKeyPath);
        var devUpdateOptIn = DevEphemeralUpdateKeyOptIn.IsInForce(options);
        IUpdateSignatureVerifier verifier;
        IReadOnlySet<string>? pinnedKeyIds;
        string? updateFailClosed = null;
        string updatePosture;
        if (hasPinnedKey)
        {
            // W24 / R-05 / D-DEC-1: the pinned key loads through the
            // ONE format-discriminating loader (Ed25519 base64 —
            // the D-DEC-1 production key — or the legacy RSA PEM).
            // A pinned file that loads as NEITHER fails CLOSED by
            // name below: a corrupt pin never crashes the Core and
            // never widens trust to an ephemeral key.
            try
            {
                verifier = PinnedUpdateKey.Create(File.ReadAllText(pinnedKeyPath));
                pinnedKeyIds = new HashSet<string> { "product-pinned" };
                updatePosture = $"pinned product update key in force (update-key.pub beside the executable); signer set = product-pinned";
            }
            catch (Exception ex)
            {
                verifier = new AbsentKeyUpdateVerifier();
                pinnedKeyIds = new HashSet<string> { "product-pinned" };
                updateFailClosed = $"pinned product update key at '{pinnedKeyPath}' could not be loaded ({ex.GetType().Name}: {ex.Message}) — update stage/apply FAIL CLOSED (DS-P9-F6 posture): a malformed pin verifies nothing and falls back to no key, never to an ephemeral one (W24/R-05)";
                updatePosture = "pinned product update key UNREADABLE — update surface FAILS CLOSED by name (W24/R-05)";
            }
        }
        else if (devUpdateOptIn)
        {
            verifier = new RsaUpdateSignatureVerifier(); // KeyId "dev-ephemeral", labelled everywhere it surfaces
            pinnedKeyIds = null;
            updatePosture = "DEV-Ephemeral update key in force under the explicit UPDATE-KEY dev opt-in (AllowDevEphemeralUpdateKey / ACP_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1) — labelled dev-ephemeral; NEVER a production posture; this posture is the update trust root only and says nothing about IPC authentication (W19/DS-B-17)";
        }
        else
        {
            verifier = new AbsentKeyUpdateVerifier();
            pinnedKeyIds = new HashSet<string> { "product-pinned" };
            updateFailClosed = $"no pinned product update key: '{pinnedKeyPath}' does not exist and no explicit update-key dev opt-in is in force — update stage/apply FAIL CLOSED (DS-P9-F6): nothing is verified, staged or applied on an ephemeral or absent key in production composition; provision update-key.pub or set the explicit update-key dev opt-in (AllowDevEphemeralUpdateKey / ACP_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1) on a dev host — ACP_DEV_ALLOW_NO_TOKEN is the IPC opt-in only and does NOT enable this posture (W19/DS-B-17)";
            updatePosture = "no pinned product update key — update surface FAILS CLOSED by name (DS-P9-F6)";
        }
        // W30 / D-DEC-7: runtime pointer-signing custody. The key
        // directory is the INSTALL ROOT (outside the data dir);
        // custody refuses by name when that resolves inside the
        // data dir, and the refusal is the composed posture —
        // named in PointerSigningStatus and the audit chain,
        // never a silent fall back to unkeyed operation claimed
        // as keyed. Keying begins here at first run (an install
        // event, which is what authorises the first pin).
        Shared.Update.PointerSigningCustody? pointerSigning = null;
        if (options.InstallRoot is not null)
        {
            var custody = new Shared.Update.PointerSigningCustody(options.InstallRoot, options.DataDir);
            if (custody.CustodyRefusal is not null)
            {
                PointerSigningStatus = custody.CustodyRefusal;
            }
            else
            {
                try
                {
                    custody.EnsureKeyForInstall();
                    pointerSigning = custody;
                    PointerSigningStatus = $"pointer signing: runtime key keyed, private half custodied in the install root '{options.InstallRoot}' (outside the data dir), public pin fingerprint {custody.Fingerprint}; rotation at each production-signed update apply (W30/D-DEC-7)";
                }
                catch (Exception ex)
                {
                    PointerSigningStatus = $"pointer signing REFUSED by name ({ex.GetType().Name}: {ex.Message}) — pointers remain in the LEGACY-UNKEYED posture, named, until custody is repaired (W30/D-DEC-7)";
                }
            }
        }
        else
        {
            PointerSigningStatus = "pointer signing NOT COMPOSED: no install root supplied to this composition — pointers remain in the named LEGACY-UNKEYED posture (W30/D-DEC-7)";
        }
        Updates = new UpdateManager(Path.Combine(options.DataDir, "updates"), verifier,
            async ct => (await SelfCheck.BuildAsync(ct)).All(h => h.Level != HealthLevel.Red),
            policyGate: version => { var d = Enterprise.CheckUpdate(version); return (d.Allowed, d.Reason); },
            pinnedKeyIds: pinnedKeyIds,
            failClosedReason: updateFailClosed,
            // W15 / DS-P9-F18 limb (b): every pointer this manager
            // writes is recorded (hash + state) in the enterprise
            // audit chain — AppendServiceAudit persists the chain —
            // so the launcher can refuse a pointer rewritten outside
            // the Core (PointerAuditAnchor).
            pointerAudit: detail =>
            {
                try { Enterprise.AppendServiceAudit(Shared.Update.PointerAuditAnchor.RecordKind, "SYSTEM", detail); } catch { }
            },
            // W36 / DS round-8: the POSITIONED seam — appends the
            // pointer record and returns its (Seq, Hash) so
            // WritePointer can sign over that exact position
            // (append-then-sign). Deliberately NOT swallow-all:
            // a failed append must refuse the keyed write by name
            // before any pointer file moves, because a pointer
            // committed without its publishing record can never
            // carry a true position commitment.
            pointerAuditPositioned: detail =>
            {
                var entry = Enterprise.AppendServiceAuditReturningEntry(Shared.Update.PointerAuditAnchor.RecordKind, "SYSTEM", detail);
                return (entry.Seq, entry.Hash);
            },
            // W30 / D-DEC-7: the runtime pointer-signing custody
            // composed above (null in the named LEGACY-UNKEYED
            // posture) + the keying-transition audit record.
            pointerSigning: pointerSigning,
            keyingAudit: detail =>
            {
                try { Enterprise.AppendServiceAudit(Shared.Update.PointerSigningCustody.KeyingRecordKind, "SYSTEM", detail); } catch { }
            },
            // W12 / DS-P9-F2: the installed-version probe — the staged
            // slot must contain the Core assembly whose file version
            // matches the staged version.
            stagedSlotProbe: static (slotDir, version) =>
            {
                try
                {
                    var dll = Path.Combine(slotDir, "Acp.Core.dll");
                    if (!File.Exists(dll)) return false;
                    var fv = System.Diagnostics.FileVersionInfo.GetVersionInfo(dll).FileVersion;
                    return fv is not null && fv.StartsWith(version.TrimStart('v'), StringComparison.Ordinal);
                }
                catch { return false; }
            });
        Tools.Register(new AgentUpdateModule(Updates, CommandGate));
        // W15 / DS-P9-F6: the composed update-signing posture is an
        // audit-chained fact, not a comment — including the
        // fail-closed and dev-ephemeral postures, by name.
        // W36 Item 3: recorded via RecordUpdateSigningPostureAudit
        // (append + verify + named FAILED state) — the swallow-all
        // try/catch W35 removed for the pointer posture is gone
        // here too.
        RecordUpdateSigningPostureAudit(updatePosture);
        RecordPointerSigningPostureAudit();

        // Files, full set.
        Tools.Register(new FileSearchModule(fileScope));
        Tools.Register(new FileInfoModule(fileScope));
        Tools.Register(new FileCopyMoveModule(fileScope, move: false));
        Tools.Register(new FileCopyMoveModule(fileScope, move: true));
        Tools.Register(new FileDeleteModule(fileScope));
        Tools.Register(new FileTransferModule(fileScope, options.DataDir));
        Tools.Register(new StagingStoreModule(fileScope));
        Tools.Register(new FileExtendedOpsModule(fileScope));

        // Registry / services / admin surfaces.
        Tools.Register(new RegistryGetModule(registry));
        Tools.Register(new RegistrySetModule(registry));
        Tools.Register(new RegistryDeleteModule(registry));
        Tools.Register(new RegistryBackupExportModule(registry, stagingRoot));
        Tools.Register(new AppInventoryModule(registry));
        Tools.Register(new ServiceListModule(serviceProvider));
        Tools.Register(new ServiceControlModule(serviceProvider, "start"));
        Tools.Register(new ServiceControlModule(serviceProvider, "stop"));
        // Block H: the restart module carries the self-restart
        // watchdog armer + the chained-audit sink — an ACP service
        // restart is watchdog-owned, never an inline stop of the
        // process being restarted (the 2026-11-20 drill defect).
        Tools.Register(new ServiceControlModule(serviceProvider, "restart",
            new Services.ProcessSelfRestartArmer(), ownServiceName: "AcpCore", auditSink: gServiceAudit));
        Tools.Register(new TaskListModule(runner));
        Tools.Register(new EventLogReadModule());
        // Block G services — MCP exposure (Block H): thin adapters
        // over the services composed above; every authorization
        // rule stays in the services and is re-read per act.
        Tools.Register(new WakeTargetsModule(Wake));
        Tools.Register(new WakeSendModule(Wake, Roster));
        Tools.Register(new TransferStartModule(StandaloneTransfers, Roster));
        Tools.Register(new TransferListModule(StandaloneTransfers, Roster));
        Tools.Register(new TransferCancelModule(StandaloneTransfers, Roster));
        Tools.Register(new FactorStatusModule(SecondFactors));
        Tools.Register(new TunnelListModule(SessionTunnels, HumanSessions, Roster));
        Tools.Register(new BatteryStatusModule(runner));
        Tools.Register(new ProcessKillModule());

        // System information + network + power.
        Tools.Register(new DeviceInfoModule());
        Tools.Register(new DiskStatusModule());
        Tools.Register(new BootStateModule(State, options.DataDir));
        Tools.Register(new PerformanceCountersModule());
        Tools.Register(new DiagnosticsBundleModule(State, selfCheckFn, Audit, stagingRoot));
        Tools.Register(new UpdateStatusModule(registry, State));
        Tools.Register(new BitLockerStatusModule(factChecks));
        Tools.Register(new SessionInventoryModule(State));
        Tools.Register(new NetPingModule());
        Tools.Register(new NetPortCheckModule());
        Tools.Register(new NetAdaptersModule());
        Tools.Register(new NetTailscaleStateModule(State));
        Tools.Register(new NetConnectionsModule());
        // U6 connection doctor: snapshots come only from state ACP
        // already owns (lane supervisor, engine events, rung attempt
        // counters, local interface facts). No probing, no mutation.
        Tools.Register(new ConnectionDoctorModule(() =>
        {
            var rungIds = new[] { "lan", "hub", "mesh", "ipv6", "ownpath", "tor" };
            var snapshots = new List<Shared.Connection.RungSnapshot>();
            foreach (var id in rungIds)
            {
                var rung = Transports.GetRung(id);
                var lastForRung = Transports.Events.LastOrDefault(e =>
                    string.Equals(e.Rung, id, StringComparison.OrdinalIgnoreCase) &&
                    e.Kind is "attempt_failed" or "session_started" or "rung_unavailable");
                var lane = id switch
                {
                    "lan" => State.Lanes?.Status(Shared.Connection.LaneKind.Lan),
                    "mesh" => State.Lanes?.Status(Shared.Connection.LaneKind.Tailscale),
                    _ => null
                };
                var configured = id switch
                {
                    "mesh" => MeshSetup.State.Stage == Shared.Tailscale.MeshSetupStage.Ready,
                    "ownpath" => File.Exists(Path.Combine(options.DataDir, "ownpath-peers.json")),
                    "tor" => File.Exists(Path.Combine(options.DataDir, "tor.json")),
                    _ => rung is not null
                };
                snapshots.Add(new Shared.Connection.RungSnapshot(
                    Id: id,
                    Registered: rung is not null && lastForRung?.Kind != "rung_unavailable",
                    Configured: configured,
                    ConnectAttempts: rung?.ConnectAttempts ?? 0,
                    LastAttemptDetail: lastForRung?.Detail,
                    LastAttemptSucceeded: lastForRung?.Kind == "session_started",
                    LaneBound: lane?.Phase == Shared.Connection.LanePhase.Bound,
                    LanePhaseName: lane?.Phase.ToString(),
                    LaneAddress: lane?.Address));
            }
            var tailnet = State.Lanes?.Status(Shared.Connection.LaneKind.Tailscale).Address;
            return new Shared.Connection.DoctorFacts(
                Shared.Connection.ConnectionDoctor.LocalInterfaceAddresses(),
                snapshots,
                TailnetAddresses: tailnet is null ? null : new[] { tailnet });
        }));
        Tools.Register(new PowerRebootModule(runner, note => Marker.AnnounceDeparture(State.ComputeState(), note)));
        Tools.Register(new PanicStopModule(State));
        Tools.Register(new AgentRestartComponentModule(restarter));
        Tools.Register(new AgentElevateModule(restarter, State));
        Tools.Register(new ScrapeModule(ScrapeModule.LoadAllowlist(options.DataDir)));

        // Claude bridge as a native module (census rows 81-82).
        var bridge = new BridgeHost(options.DataDir, runner, () => State.StopInForce);
        Tools.Register(new BridgeQueueModule(bridge));
        Tools.Register(new BridgeRunModule(bridge));

        // RMM-10 background tools (BD-WIN-CORE-1 F4): registered
        // ONLY when the management policy enables the toolset for
        // this device (the modules' own surface law), each bound to
        // this device's real id so facts resolve and calls fail
        // closed on their own merits — never on an empty device id.
        // RESIDUAL (named): the executor under BackgroundTools is
        // still the recording stub composed above; enabling the
        // policy surfaces tools whose executor performs no OS
        // mutation yet. That stub is the RMM-10 lane's wiring
        // remainder, not hidden here.
        try
        {
            var bgFacts = Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "");
            if (new Shared.BackgroundTools.BackgroundToolSurface(policyEngine).ToolsetEnabled(bgFacts))
            {
                Tools.Register(new BackgroundProcessKillModule(BackgroundTools, () => Identity.DeviceId));
                Tools.Register(new BackgroundProcessKillTreeModule(BackgroundTools, () => Identity.DeviceId));
                Tools.Register(new BackgroundServiceControlModule(BackgroundTools, "start", () => Identity.DeviceId));
                Tools.Register(new BackgroundServiceControlModule(BackgroundTools, "stop", () => Identity.DeviceId));
                Tools.Register(new BackgroundServiceControlModule(BackgroundTools, "restart", () => Identity.DeviceId));
                Tools.Register(new BackgroundFileListModule(BackgroundTools, () => Identity.DeviceId));
                Tools.Register(new BackgroundRegistrySetModule(BackgroundTools, () => Identity.DeviceId));
                Tools.Register(new BackgroundKitRunModule(BackgroundTools, () => Identity.DeviceId));
            }
        }
        catch { /* policy surface computation failed: the toolset stays unregistered (fail closed) */ }

        // Batch / presence / notify.
        Tools.Register(new BatchActionsModule(Ipc, Policy, Tools, Audit));
        Tools.Register(new PresenceControlModule(Ipc, State, Sessions));
        Tools.Register(new TakeoverStatusModule(State));
        Tools.Register(new NotifyUserModule(Ipc, options.DataDir, AgentEvents));
        Tools.Register(new EventsSubscribeModule(EventSubscriptions));
        Tools.Register(new EventsUnsubscribeModule(EventSubscriptions));

        // Desktop plane: the full proxied descriptor set.
        foreach (var d in DesktopToolDescriptors.All())
            Tools.Register(new ProxiedModule(Ipc, d));

        // Agent-side engines that report honestly until their engines
        // land (Phase 2 census rows; the agent answers not-implemented
        // rather than pretending).
        foreach (var (name, desc, scope, risk) in new[]
        {
            ("camera_capture", "Capture a still from a camera in the signed-in user's session.", Scopes.Observe, RiskTier.Medium),
            ("microphone_capture", "Capture a short audio clip in the signed-in user's session.", Scopes.Drive, RiskTier.High),
            ("speaker_playback", "Play audio through the session's speakers.", Scopes.Drive, RiskTier.Medium),
            ("screen_record", "Record the screen for a bounded duration.", Scopes.Drive, RiskTier.High),
            ("av_stream_capture", "Stream audio/video from the session.", Scopes.Drive, RiskTier.High),
            ("notifications_manage", "Read/dismiss Windows notifications in the signed-in user's session.", Scopes.Drive, RiskTier.Medium),
            ("office_com_automation", "Drive Office applications through COM automation in the signed-in user's session.", Scopes.Drive, RiskTier.High),
            ("touch_gesture", "Touch gestures (pinch/swipe) on touch hardware.", Scopes.Drive, RiskTier.High),
        })
            Tools.Register(new ProxiedModule(Ipc, new ToolDescriptor(name, desc, scope, SessionRequirement.Agent, risk, null, "Agent")));

        // Phase 2: unlock, child sessions, Safe Mode.
        ICredentialVault vault = OperatingSystem.IsWindows() ? new LsaCredentialVault() : new InMemoryCredentialVault();
        // BD-WIN-CORE-1 F11: no hardcoded owner account. The logon
        // user comes from installer config (ACP_LOGON_USER); when it
        // is not configured the unlock channel is the fake (refuses
        // honestly) rather than targeting a guessed account name.
        var logonUser = Environment.GetEnvironmentVariable("ACP_LOGON_USER");
        ICredentialProviderChannel cpChannel = OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(logonUser)
            ? new PipeCredentialProviderChannel(logonUser, Environment.MachineName)
            : new FakeCredentialProviderChannel();
        Unlock = new UnlockService(vault, cpChannel, factChecks, () => State.StopInForce,
            Sessions, () => State.Session.DesktopUnlocked);
        // The unlock module ships ENABLED at the Core level (install-night
        // defect #5, 2026-11-14: the flag defaulted false and NOTHING in
        // the product could set it, so the module reported "Disabled"
        // forever — including immediately after a successful vault
        // seeding, which read to the owner as a failed store). Enablement
        // is not the operative safety gate: an unlock still requires the
        // dedicated `unlock` pairing scope (granted by no preset), the
        // credential provider registered (a supervised step), a seeded
        // vault, no STOP in force, and the one-attempt brake. The flag
        // stays settable so a future owner toggle can drive it.
        Unlock.ModuleEnabled = true;
        Tools.Register(new SessionUnlockModule(Unlock));
        Tools.Register(new SessionRelockModule(Sessions, Ipc));
        IChildSessionDriver childDriver = OperatingSystem.IsWindows() ? new WindowsChildSessionDriver() : new FakeChildSessionDriver();
        Tools.Register(new ChildSessionModule(new ChildSessionManager(childDriver, factChecks)));
        SafeMode = new SafeModeOrchestrator(runner, options.DataDir);
        Tools.Register(new SafeModeRebootModule(SafeMode));

        // Owner Console (fleet board, takeover arbitration, live view).
        Fleet = new FleetBoard();
        Takeover = new TakeoverArbiter(State, Audit);
        Tools.Register(new FleetBoardModule(Fleet, State, Sessions, Environment.MachineName));
        Tools.Register(new OwnerTakeoverModule());
        Tools.Register(new TakeoverHandBackRequestModule()); // FR-120 (W73): the gated ASK for control back — approval, never the act, is agent-reachable
        // C20 wiring: the agent-facing recovery surface is a refusal
        // only (OwnerRecoveryService carries the owner-local acts).
        Tools.Register(new Services.RecoveryBlobModule());
        Tools.Register(new LiveViewModule(new LiveViewService(Ipc, State, Audit,
            Environment.GetEnvironmentVariable("ACP_OWNER_NAME") ?? "the owner")));

        // Phase 2 long tail + engines.
        var alertRules = new HealthAlertRules(Path.Combine(options.DataDir, "health-alert-rules.json"));
        var scriptPolicy = new ScriptSignaturePolicy(options.DataDir);
        // BD-WIN-CORE-1 F12: ONE tunnel allowlist governs both the
        // agent tool and the session-tunnel service — the merged
        // env + tunnel-allowlist.json set LoadTunnelAllowlist builds.
        var tunnelAllow = LoadTunnelAllowlist(options.DataDir) ?? new HashSet<string>();
        var sshAllow = new HashSet<string>((Environment.GetEnvironmentVariable("ACP_SSH_ALLOWLIST") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        Missions = new MissionEngine(options.DataDir);
        Tools.Register(new MissionEngineModule(Missions));
        var macroModule = new MacroModule(options.DataDir, Ipc);
        Tools.Register(macroModule);
        Tools.Register(new ScriptSignaturePolicyModule(scriptPolicy, Audit));
        Tools.Register(new ScriptEnginesModule(runner, fileScope, scriptPolicy, verifier));
        Tools.Register(new RemoteShellModule(runner, sshAllow));
        Tools.Register(new ToolModuleInstallModule(options.DataDir, verifier, scriptPolicy));
        Tools.Register(new BrowserControlModule());
        Tools.Register(new CredentialInjectServiceModule());
        // BD-WIN-CORE-1 F12: WakeOnLanModule is NOT registered —
        // it duplicated WakeService/WakeSendModule outside policy
        // control. Wake-on-LAN is served by wake_on_lan_send's
        // sibling (Block G WakeSendModule over WakeService) only.
        Tunnels = new TcpTunnelService(tunnelAllow, (kind, pairingId, detail) =>
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairingId, null, "tcp_tunnel", null, null, $"{kind}:{detail}", "SYSTEM", null)));
        Tools.Register(new TcpTunnelModule(Tunnels));
        Tools.Register(new CertEnvAdminModule());
        Tools.Register(new HealthAlertRulesModule(alertRules));
        Tools.Register(new SerialPortModule());
        Tools.Register(new DeviceLocationModule());
        Tools.Register(new PackageManageModule(runner));
        Tools.Register(new PatchManageModule(runner));
        Tools.Register(new DefenderManageModule(runner));
        Tools.Register(new UserGroupAdminModule(runner));
        Tools.Register(new SystemRepairModule(runner));
        Tools.Register(new MappedDrivesModule(runner));
        Tools.Register(new PrinterControlModule(runner));
        Tools.Register(new DeviceInventoryModule(runner, "usb"));
        Tools.Register(new DeviceInventoryModule(runner, "bluetooth"));
        Tools.Register(new BluetoothControlModule(runner));
        Tools.Register(new AudioModule(runner, "volume"));
        Tools.Register(new AudioModule(runner, "devices"));
        Tools.Register(new EventLogManageModule(runner));
        Tools.Register(new TaskRunModule(runner));
        Tools.Register(new VulnerabilityScanModule(runner));

        // Signed plugin modules installed through tool_module_install.
        // Load-time signature re-verification (2026-11-15 blocker fix).
        var (pluginModules, pluginErrors) = ToolModuleInstallModule.LoadInstalled(Path.Combine(options.DataDir, "plugins"), verifier, scriptPolicy.SignedOnly);
        foreach (var plugin in pluginModules) Tools.Register(plugin);
        _pluginErrors = pluginErrors;

        // LAN lane TLS (H1 remainder closure): the host certificate is
        // generated on first start into the ACL'd data dir; its pin is
        // disclosed only inside a successful pairing exchange.
        // BD-WIN-CORE-3/F11: the PFX password is sealed with the
        // runtime ISecretProtector, and a corrupt-store regeneration
        // (pin change) is chained-audited, never silent.
        LanTls = new LanCertificateStore(options.DataDir, protector,
            detail => Audit.Append(new Shared.Audit.AuditEntry(DateTimeOffset.UtcNow,
                "system", null, null, null, null, null, detail, null, null)));
        var lanCert = LanTls.EnsureCertificate();

        // Hub component wiring (Block C part 2): the vault persists
        // write-through like the other stores (protector-wrapped secrets
        // only — hub-apikeys.json never holds a plaintext key, HS-02).
        // The lifecycle is constructed dormant: Hub.Start() refuses
        // unless the hub rung was selected for a scope (D16).
        // BD-SHARED-TRANSPORT F2: hub keys are issued by
        // Headscale itself through the CLI authority over the
        // bundled binary — the vault/join services store and
        // consume issued keys and refuse to mint without it.
        var hubHome = Path.Combine(options.DataDir, "hub");
        var hubAuthority = new HeadscaleCliKeyAuthority(
            Path.Combine(hubHome, OperatingSystem.IsWindows() ? "headscale.exe" : "headscale"),
            Path.Combine(hubHome, "config.yaml"));
        HubApiKeys = new HubApiKeyVault(protector, hubAuthority);
        var hubKeysPath = Path.Combine(options.DataDir, "hub-apikeys.json");
        if (File.Exists(hubKeysPath))
        {
            try { HubApiKeys.ImportJson(File.ReadAllText(hubKeysPath)); } catch { }
        }
        HubApiKeys.Changed += () =>
        {
            try { WriteStoreAtomic(hubKeysPath, HubApiKeys.ExportJson()); } catch { }
        };
        HubNodes = new HubNodeRegistry(new ClientVersionGate());
        HubJoins = new HubJoinService(protector, HubNodes, hubAuthority);
        // HS-07 wiring: any enrollment-roster change reconciles hub
        // membership — a device removed from ACP loses its hub NODE
        // (deleted, not key-expired). The admin commands are audited;
        // executing them against a running hub is the lifecycle's job
        // when the hub rung is live.
        Enrollments.Changed += () =>
        {
            try
            {
                var live = Enrollments.List().Where(d => !d.Revoked)
                    .Select(d => d.DeviceId).ToHashSet();
                // BD-SHARED-TRANSPORT F2: keep the registry's
                // Headscale numeric node ids current from the
                // hub's own node list, so Decommission can name a
                // real node (it refuses while the id is unknown).
                try
                {
                    foreach (var (devId, nodeId) in hubAuthority.ListNodeIds(live))
                        HubNodes.RecordHeadscaleNodeId(devId, nodeId);
                }
                catch { /* hub not running — ids refresh on the next change */ }
                foreach (var cmd in HubNodes.ReconcileDeletions(live, DateTimeOffset.UtcNow))
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null,
                        "hub", "node_delete_on_device_removal", cmd, "executed", "SYSTEM", null));
            }
            catch { }
        };
        Hub = new HubLifecycle(new HubOptions
        {
            ComponentHome = Path.Combine(options.DataDir, "hub"),
            ServerUrl = options.HubServerUrl,
        }, new HubProcess(), options.HubRungSelected);
        TorSetup = new Shared.Tor.TorSetupService(
            new Shared.Tor.TorProvisioner(Shared.Tor.TorComponentManifest.Production),
            new TorProcess(),
            Path.Combine(options.DataDir, "tor"),
            options.DataDir);

        Mcp = new McpHandler(Pairings, Policy, Tools, Audit, State, Sessions, options.DataDir);
        Mcp.Events = AgentEvents;
        // W9: the GateSheet's live caller — a gate-denied call in a
        // live session raises the §3 sheet at the endpoint through
        // the broker + agent IPC; Deny-and-end's teardown lands here
        // AFTER the handler's audit-first entry (see McpHandler).
        Mcp.GateRaiser = RaiseGateForSessionAsync;
        Mcp.GateDenyAndEndTeardown = OnGateDenyAndEndTeardown;
        // U4 TOTAL POLICY CONTROL wiring: session budgets read the
        // RMM-07 effective policy for THIS device — the registered
        // toggle "rmm.session_budget.enabled" (default ON) gates the
        // layer, and "session_budget.cap.<class>" settings override
        // the named default caps. Resolved per call, so an admitted
        // policy document takes effect without a restart.
        Mcp.BudgetCapsProvider = () =>
        {
            var facts = Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "");
            if (!ManagementPolicies.IsEnabled(facts, "rmm.session_budget.enabled")) return null;
            return Shared.Policy.SessionBudgetCaps.FromEffective(ManagementPolicies.ComputeEffective(facts));
        };
        // U1 TOTAL POLICY CONTROL wiring: the clipboard direction
        // layer reads the RMM-07 effective policy for THIS device —
        // the registered toggle "rmm.clipboard_policy.enabled"
        // (default ON) gates the layer, and the plain settings keys
        // "clipboard.direction" / "clipboard.sensitive_skip" carry
        // the owner's direction + skip choices. Resolved per call,
        // so an admitted policy document takes effect without a
        // restart; the resolved policy is also pushed to the
        // session agent (PushClipboardPolicySafelyAsync) so the
        // desktop engine enforces it at the clipboard itself.
        Sessions.ClipboardPolicyProvider = () =>
        {
            var facts = Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "");
            if (!ManagementPolicies.IsEnabled(facts, ClipboardPolicyKeys.FeatureToggle)) return null;
            return ClipboardPolicy.FromEffective(ManagementPolicies.ComputeEffective(facts));
        };
        Missions.StepRunner = (pairingId, tool, args, ct) => Mcp.ExecuteForPairingAsync(pairingId, tool, args, ct);
        // BD-WIN-CORE-2/F4+F9 wiring: missions halt when their creating
        // pairing dies; stale 'running' missions recover to 'paused' at
        // start; macro replay steps run through the same choke point.
        Missions.PairingStillValid = pairingId => Pairings.List().Any(p => p.Id == pairingId && !p.Revoked
            && (p.ExpiresUtc is null || p.ExpiresUtc > DateTimeOffset.UtcNow));
        try { Missions.RecoverStaleRuns(); } catch { /* recovery is best-effort at construct; module list re-runs it */ }
        macroModule.PolicyStepRunner = (pairingId, tool, args, ct) => Mcp.ExecuteForPairingAsync(pairingId, tool, args, ct);
        var pairingHandler = new PairingHandler(Pairings, Audit, () => LanTls.Fingerprint, EventSubscriptions);
        // Mesh companion server (M2): the phone's device page talks
        // to these routes on the tailnet lane; facts come straight
        // from the session/state stores, never cached copies.
        Mesh = new Services.MeshService(Ipc,
            () => Sessions.Current,
            () => Sessions.ActionCount,
            () => State.Session.DesktopUnlocked,
            () => State.LastNarration,
            humanSessions: () => SessionPicture.All(HumanSessions, Roster, DateTimeOffset.UtcNow),
            stopInForce: () => State.StopInForce);
        var mesh = Mesh;
        // Session stream (Block D): H.264 stream bound to the Slice 3
        // session model, floor-gated at the stream layer. Capture +
        // encode live in the Session Agent; this service is the
        // session/floor authority every frame and input passes.
        Stream = new Services.StreamService(Ipc, HumanSessions,
            () => State.Session.DesktopUnlocked,
            () => State.StopInForce,
            displayName: (scope, user) => Roster.GetUser(scope, user)?.DisplayName,
            // U5: stream frame bytes land in the same flow ledger
            // the MCP choke point counts into (Mcp is built above).
            flows: Mcp.Flows);
        // BD-WIN-CORE-3/F1 (built): the mesh identity is the v2
        // pairing channel's authenticated identity — the request's
        // pairing bearer token resolves through Pairings (the same
        // authentication McpHandler applies) and the host-bound
        // pairing name to the unique live roster user.
        MeshIdentity = new Services.MeshIdentityResolver(Pairings, Roster);
        LaneHosts = new LaneHostManager(Mcp, pairingHandler, ReadApprovedGates, options.Port, lanCert, mesh, Stream, QuickAssist,
            meshIdentity: http => MeshIdentity.ResolveUserId(http.Request.Headers.Authorization.ToString()));

        var launcher = options.AgentLauncher ?? (OperatingSystem.IsWindows()
            ? new WindowsAgentLauncher(() => ipcToken)
            : new ProcessStartAgentLauncher());
        Watchdog = new AgentWatchdog(State, Ipc, launcher, Audit, options.AgentExePath);
    }

    /// <summary>W35: append the pointer-signing posture to the
    /// enterprise chain — and PROVE it landed. Audit-first
    /// discipline: any failure (the append throws, the entry is
    /// not in the chain afterwards, or chain persistence reports
    /// BROKEN) becomes the named PointerSigningPostureAuditState
    /// error state instead of vanishing into a swallow-all catch
    /// (the W33-B live finding: keying began, the chain held zero
    /// "pointer" entries, nothing said so).</summary>
    private void RecordPointerSigningPostureAudit()
    {
        try
        {
            if (_options.PointerSigningPostureAuditSink is { } sink)
                sink("pointer_signing_posture", "SYSTEM", PointerSigningStatus);
            else
                Enterprise.AppendServiceAudit("pointer_signing_posture", "SYSTEM", PointerSigningStatus);
        }
        catch (Exception ex)
        {
            PointerSigningPostureAuditState =
                $"FAILED: pointer_signing_posture audit append failed ({ex.GetType().Name}: {ex.Message}) — the pointer-signing posture is NOT recorded in the enterprise chain (W35 named error state, not silence)";
            return;
        }
        if (_options.PointerSigningPostureAuditSink is not null)
        {
            PointerSigningPostureAuditState = "recorded:pointer_signing_posture (via the composed audit sink)";
            return;
        }
        // W43 (F2): "landed" now means DURABLE — present in the
        // in-memory chain AND in the persisted store a restart
        // would import (Enterprise.ChainEntryIsDurable reads the
        // actual file). The W35 check trusted the in-memory chain
        // + the last-save state flag, and the pre-fix save race
        // could overwrite the entry while the flag still read ok
        // (W42 boot 1: verified append, persisted chain at the
        // previous entry, zero "pointer" entries).
        var inChain = Enterprise.AuditLog.Entries.Any(e => e.Kind == "pointer_signing_posture");
        var durable = inChain && Enterprise.ChainEntryIsDurable("pointer_signing_posture");
        PointerSigningPostureAuditState = !inChain
            ? "FAILED: pointer_signing_posture audit append returned without error but the entry is NOT in the enterprise chain — the posture is NOT recorded (W35 named error state, not silence)"
            : !durable
                ? $"FAILED: pointer_signing_posture is in the in-memory chain but is NOT durable in the persisted chain (chain persistence is {Enterprise.ChainPersistenceState}) — the posture would NOT survive a restart (W43 named error state, not silence)"
                : "recorded:pointer_signing_posture";
    }

    /// <summary>W36 Item 3: the W35 treatment for the neighbouring
    /// update_signing_posture append, minimal scope — append, then
    /// PROVE the landing (entry present in the chain AND chain
    /// persistence ok); any failure becomes the named
    /// UpdateSigningPostureAuditState FAILED state instead of the
    /// swallow-all catch this append used before.</summary>
    private void RecordUpdateSigningPostureAudit(string updatePosture)
    {
        try
        {
            if (_options.UpdateSigningPostureAuditSink is { } sink)
                sink("update_signing_posture", "SYSTEM", updatePosture);
            else
                Enterprise.AppendServiceAudit("update_signing_posture", "SYSTEM", updatePosture);
        }
        catch (Exception ex)
        {
            UpdateSigningPostureAuditState =
                $"FAILED: update_signing_posture audit append failed ({ex.GetType().Name}: {ex.Message}) — the update-signing posture is NOT recorded in the enterprise chain (W36 named error state, not silence)";
            return;
        }
        if (_options.UpdateSigningPostureAuditSink is not null)
        {
            UpdateSigningPostureAuditState = "recorded:update_signing_posture (via the composed audit sink)";
            return;
        }
        // W43 (F2): durable-landing check, as the pointer posture
        // above — in-memory presence alone no longer reads
        // "recorded".
        var inChain = Enterprise.AuditLog.Entries.Any(e => e.Kind == "update_signing_posture");
        var durable = inChain && Enterprise.ChainEntryIsDurable("update_signing_posture");
        UpdateSigningPostureAuditState = !inChain
            ? "FAILED: update_signing_posture audit append returned without error but the entry is NOT in the enterprise chain — the posture is NOT recorded (W36 named error state, not silence)"
            : !durable
                ? $"FAILED: update_signing_posture is in the in-memory chain but is NOT durable in the persisted chain (chain persistence is {Enterprise.ChainPersistenceState}) — the posture would NOT survive a restart (W43 named error state, not silence)"
                : "recorded:update_signing_posture";
    }

    private readonly HashSet<string> _approvedGates = new();
    private readonly object _gatesLock = new();

    /// <summary>Crash-safe store write (D38 F11): serialize to a
    /// sibling temp file, then replace the store in one move — a
    /// crash mid-write can never leave a truncated store behind for
    /// the next boot's import to choke on.</summary>
    /// <summary>RMM-03 state, named honestly: "wired" only when a
    /// customer command key ring actually loaded.</summary>
    public string CommandGateState { get; private set; } =
        "not loaded yet";

    /// <summary>RMM-03 persisted replay-guard state, named honestly
    /// (fresh / loaded: N / BROKEN — a broken store refuses every
    /// registration, fail closed).</summary>
    public string NonceStoreState { get; private set; } = "not loaded yet";

    /// <summary>Load the customer command PUBLIC key ring
    /// (customer-command-keys.json: [{keyId, publicKeyBase64,
    /// retiredUntilUtc}]). The stored keyId must match the key it
    /// names (KeyIdFor) — a relabelled key refuses the whole ring
    /// rather than trusting the label. Any failure leaves the gate
    /// unwired and names why; nothing here can widen trust.</summary>
    private Shared.Security.SignedCommandGate? LoadCommandGate(string dataDir)
    {
        var path = Path.Combine(dataDir, "customer-command-keys.json");
        if (!File.Exists(path))
        {
            CommandGateState = "UNWIRED: no customer command key configured (customer-command-keys.json absent) — shell/session/update paths keep their pre-RMM-03 posture; signed-command coverage is NOT claimed";
            return null;
        }
        try
        {
            var ring = new Shared.Security.CustomerCommandKeyRing();
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            var count = 0;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var pub = Convert.FromBase64String(el.GetProperty("publicKeyBase64").GetString() ?? "");
                var namedId = el.GetProperty("keyId").GetString() ?? "";
                if (namedId != Shared.Security.CustomerCommandKeyRing.KeyIdFor(pub))
                {
                    CommandGateState = $"UNWIRED: customer-command-keys.json names key '{namedId}' but the key material fingerprints to '{Shared.Security.CustomerCommandKeyRing.KeyIdFor(pub)}' — ring refused (key-id confusion never widens trust)";
                    Enterprise.AuditLog.Append("signed_command_refused", "signed-command-gate", CommandGateState, DateTimeOffset.UtcNow);
                    return null;
                }
                var retiredUntil = el.TryGetProperty("retiredUntilUtc", out var ru) && ru.ValueKind != System.Text.Json.JsonValueKind.Null
                    ? ru.GetDateTimeOffset() : (DateTimeOffset?)null;
                if (retiredUntil is null) ring.AddCurrent(pub);
                else ring.AddRetired(pub, retiredUntil.Value);
                count++;
            }
            if (count == 0)
            {
                CommandGateState = "UNWIRED: customer-command-keys.json carried no keys — ring refused";
                return null;
            }
            _commandKeyRing = ring;
            // RMM-02 precondition (RMM-03 residual closure): the
            // replay guard is PERSISTED — seen nonces live in
            // signed-command-nonces.json (temp+replace, expiry-
            // pruned), so a replayed envelope refuses across Core
            // restarts, not only within one process lifetime.
            var nonceStore = new Shared.Security.PersistedNonceStore(Path.Combine(dataDir, "signed-command-nonces.json"));
            NonceStoreState = nonceStore.State;
            CommandGateState = $"wired: {count} customer command key(s) loaded — shell_exec, session_initiation and update stage_signed REQUIRE verified signed commands (RMM-03); replay guard persisted ({NonceStoreState})";
            Enterprise.AuditLog.Append("signed_command_gate_wired", "signed-command-gate", CommandGateState, DateTimeOffset.UtcNow);
            return new Shared.Security.SignedCommandGate(
                new Shared.Security.SignedCommandVerifier(ring,
                    new Shared.Security.PersistedSignedCommandReplayGuard(nonceStore),
                    // D38 F1: envelopes verify only when their signed
                    // audience names THIS endpoint (Identity.DeviceId)
                    // — a captured envelope cannot replay fleet-wide.
                    expectedAudience: Identity.DeviceId), Enterprise.AuditLog);
        }
        catch (Exception ex)
        {
            CommandGateState = $"UNWIRED: customer command key ring unreadable ({ex.GetType().Name}) — refused to wire (fail closed to the named pre-RMM-03 posture, never to silent trust)";
            return null;
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> _storeLocks = new();
    private static long _storeWriteFailures;
    /// <summary>BD-WIN-CORE-1 F12: durable-store write failures are
    /// counted here instead of vanishing into empty catch blocks —
    /// the self-check / operator can see the count; a failed write
    /// never corrupts the previous store (unique temp + per-store
    /// lock + atomic replace).</summary>
    public static long StoreWriteFailures => Interlocked.Read(ref _storeWriteFailures);

    private static void WriteStoreAtomic(string path, string content)
    {
        var gate = _storeLocks.GetOrAdd(path, _ => new object());
        lock (gate)
        {
            var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(tmp, content);
                File.Move(tmp, path, overwrite: true);
            }
            catch
            {
                Interlocked.Increment(ref _storeWriteFailures);
                try { File.Delete(tmp); } catch { }
                throw;
            }
        }
    }

    /// <summary>Lane A hub-persistence loader: restore a store file
    /// through its integrity-checked ImportJson. Recovery behaviour
    /// is STRONGER than the RMM-04 template's silent catch: when the
    /// file exists but imports nothing AND fails to parse as its
    /// envelope at all, the bytes are preserved under a
    /// .corrupt-<timestamp> name (never overwritten, never silently
    /// dropped) and the store starts empty. Returns the number of
    /// records restored (0 when the file was absent, empty, or an
    /// intact envelope that legitimately restored nothing).</summary>
    private static int RestoreHubStore(string path, Func<string, int> import, string envelopeKind)
    {
        if (!File.Exists(path)) return 0;
        string text;
        try { text = File.ReadAllText(path); } catch { return 0; }
        var restored = 0;
        try { restored = import(text); } catch { restored = 0; }
        if (restored == 0 && Shared.Hub.HubPersistence.Unwrap(text, envelopeKind) is null
            && !string.IsNullOrWhiteSpace(text))
        {
            try
            {
                var corruptPath = path + ".corrupt-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
                if (File.Exists(corruptPath))
                    corruptPath += "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                File.Move(path, corruptPath);
            }
            catch { /* preservation is best-effort; empty start proceeds */ }
        }
        return restored;
    }

    /// <summary>The gate classes currently approved (startup file state
    /// plus everything approved since over the authenticated agent IPC).</summary>
    public IReadOnlySet<string> ApprovedGateClasses => ReadApprovedGates();

    /// <summary>Apply one gate approval/unapproval from the laptop UI.
    /// Called ONLY from the authenticated agent-IPC event (C3): there
    /// is deliberately no file, tool, or HTTP path into this method —
    /// the Session Agent's approval buttons are the single runtime
    /// source. Returns false for malformed payloads (ignored, audited
    /// nowhere, never fatal).</summary>
    public bool TryApplyGateApproval(string? argumentsJson)
    {
        if (argumentsJson is null) return false;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var gate = doc.RootElement.TryGetProperty("gate", out var g) ? g.GetString() : null;
            var approved = doc.RootElement.TryGetProperty("approved", out var a) && a.ValueKind == JsonValueKind.True;
            if (gate is null) return false;
            lock (_gatesLock) { if (approved) _approvedGates.Add(gate); else _approvedGates.Remove(gate); }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"gate_{(approved ? "approved" : "unapproved")}_via_agent:{gate}", "SYSTEM", null));
            return true;
        }
        catch { return false; /* malformed approval message: ignored, never fatal */ }
    }

    /// <summary>The host-state snapshot for the companion window (M4):
    /// built from live Core facts only — pairings, gate approvals,
    /// the session record, the audit tail. No secrets are in it.
    /// Block A (2026-11-19): the snapshot also carries the LIVE Slice 2
    /// roster (per-scope operator shape), the LIVE Slice 3 human
    /// sessions (SessionPicture), and this device's D2 endpoint view —
    /// all read from the stores at build time, all facts only
    /// (enrolled devices carry no key material in this document).</summary>
    public string BuildHostStateJson()
    {
        var now = DateTimeOffset.UtcNow;
        var cur = Sessions.Current;
        var humanFacts = SessionPicture.All(HumanSessions, Roster, now);
        var primaryHuman = SessionPicture.PrimaryLive(HumanSessions, Roster, now);
        // The headline session facts describe the controlling
        // session in the one picture: the agent (MCP) session when
        // live, else the primary live human session.
        var facts = cur is not null
            ? new HostStateSnapshot.SessionFacts(
                Active: true,
                AgentName: cur.ActorAgentName,
                Seconds: Math.Max(0, (long)(now - cur.StartedUtc).TotalSeconds),
                Actions: Sessions.ActionCount,
                Intent: State.LastNarration)
            : primaryHuman is not null
                ? new HostStateSnapshot.SessionFacts(
                    Active: true,
                    AgentName: primaryHuman.InitiatorName,
                    Seconds: primaryHuman.Seconds,
                    Actions: primaryHuman.Actions,
                    Intent: State.LastNarration)
                : new HostStateSnapshot.SessionFacts(false, null, 0, 0, State.LastNarration);
        return HostStateSnapshot.Build(
            coreVersion: typeof(CoreRuntime).Assembly.GetName().Version?.ToString() ?? "unknown",
            machineName: Environment.MachineName,
            port: _options.Port,
            runningLanes: LaneHosts.RunningLanes,
            agentConnected: State.Session.AgentConnected,
            desktopUnlocked: State.Session.DesktopUnlocked,
            userStopInForce: State.StopInForce,
            session: facts,
            pairings: Pairings.List(),
            gatedClasses: Acp.Shared.Policy.PolicyEngine.GatedClasses,
            approvedGates: ReadApprovedGates(),
            auditTail: Audit.ReadTail(60),
            roster: BuildRosterFacts(),
            humanSessions: humanFacts.Select(h => h with { TerminalOpen = Terminals.OpenTerminalFor(h.Id) is not null }).ToList(),
            endpoint: BuildEndpointFact(),
            transport: BuildTransportFacts(),
            enterprise: BuildEnterpriseFact(),
            blockG: BuildBlockGFact(),
            mesh: BuildMeshFact(),
            // U5: the full multi-agent flow report — this snapshot
            // is the owner's surface, the one place all pairings'
            // flows appear together.
            dataFlows: Mcp.Flows is { } flowLedger
                ? DataFlowReport.Build(flowLedger.Records(), Audit.ReadTail(5000))
                : null,
            eventWatches: EventSubscriptions.ListAll(),
            recovery: new HostStateSnapshot.RecoveryFact(
                Identity.DeviceId,
                Recovery.LastExportUtc, Recovery.LastRestoreUtc,
                Recovery.LastRestoredDeviceId, Recovery.LastRestorePairings,
                Recovery.LastRestoreRosterEntries),
            // FR-113 (W65): effective roots = configured roots, else
            // the staging-only fallback the FileScope actually uses.
            fileRoots: _options.FileRoots.Count > 0
                ? _options.FileRoots
                : new[] { Path.Combine(_options.DataDir, "staging") },
            // W97: the live last-seen rung per pairing (this run).
            lastConnection: id => Pairings.LastConnection(id),
            // W122 / N22: the inbox index over the one chat store.
            chatThreads: BuildChatThreadFacts());
    }

    /// <summary>W122 / N22: per-pairing inbox facts for the host
    /// snapshot, computed from the ONE thread store (AgentChatStore
    /// + ChatOrderStore + ChatSeenStore) at snapshot time — the
    /// inbox is an index, never a second store, so its counts can
    /// never drift from the threads themselves. Revoked pairings
    /// carry no thread (unpair ended it) and are skipped.</summary>
    private IReadOnlyList<HostStateSnapshot.ChatThreadFact> BuildChatThreadFacts()
    {
        var result = new List<HostStateSnapshot.ChatThreadFact>();
        foreach (var p in Pairings.List())
        {
            if (p.Revoked) continue;
            var messages = Chat.Load(p.Id);
            var orders = Orders.Load(p.Id);
            var facts = Shared.Sessions.ChatInboxModel.Summarize(p.Id, messages, orders, ChatSeen.Load(p.Id));
            var pending = orders
                .Where(o => o.Status == Shared.Sessions.ChatOrderStatus.Pending)
                .OrderBy(o => o.CreatedAtMs)
                .Select(o => new HostStateSnapshot.ChatPendingOrderFact(
                    o.Id, o.Tool, o.GateClass, o.ArgumentsJson, o.Title, o.TargetDevice, o.CreatedAtMs))
                .ToArray();
            result.Add(new HostStateSnapshot.ChatThreadFact(
                p.Id, facts.UnreadMessages, facts.PendingOrders, facts.LastActivityMs, pending));
        }
        return result;
    }

    /// <summary>Mesh facts for the snapshot (Block H tray fix):
    /// the mesh companion's live state + phone facts, read from
    /// the MeshService at build time — the same truth /mesh/state
    /// serves the phone, now also reaching the agent surfaces that
    /// cannot (and must not) fetch it over loopback HTTP.</summary>
    private HostStateSnapshot.MeshFact BuildMeshFact()
    {
        var (phone, watching) = Mesh.PhoneFacts;
        return new HostStateSnapshot.MeshFact(Mesh.CurrentState, phone, watching);
    }

    /// <summary>Block G facts for the snapshot (2026-11-20):
    /// counts from the live G services + the eight TOTAL POLICY
    /// CONTROL postures from the loaded bundle. Rebuilt on every
    /// snapshot, so the window always shows the CURRENT truth.</summary>
    private HostStateSnapshot.BlockGFact BuildBlockGFact()
    {
        var (totpActive, passkeys) = SecondFactors.Counts();
        var states = new Dictionary<string, string>();
        foreach (var key in Acp.Shared.Enterprise.PolicyFeatures.All)
            states[key] = Enterprise.FeatureState(key);
        return new HostStateSnapshot.BlockGFact(
            WakeTargets: Wake.ListTargets().Count,
            StandaloneJobsLive: StandaloneTransfers.LiveJobCount(),
            TotpEnrollmentsActive: totpActive,
            PasskeysRegistered: passkeys,
            SessionTunnelsOpen: SessionTunnels.ListOpen().Count,
            FeatureStates: states);
    }

    /// <summary>Enterprise facts for the snapshot (Block F): policy
    /// state, the chained audit's verdict, alert count, pending
    /// break-glass rotation — read live from the EnterpriseService
    /// every snapshot, so the window always shows the CURRENT truth.</summary>
    private HostStateSnapshot.EnterpriseFact BuildEnterpriseFact()
    {
        var verdict = Enterprise.AuditLog.Verify();
        return new HostStateSnapshot.EnterpriseFact(
            PolicyState: Enterprise.PolicyState,
            PolicyLoaded: Enterprise.Enforcer is not null,
            ChainOk: verdict.Ok,
            ChainSummary: verdict.Summary,
            AlertCount: Enterprise.Alerts.Alerts.Count,
            BreakGlassRotationRequired: Enterprise.BreakGlass.RotationRequired,
            RealIdpBoundary: Services.EnterpriseService.RealIdpBoundary,
            // W43 (F2b): the posture-audit states are observable on
            // this live surface — a named FAILED state no longer
            // requires reading the chain file to discover.
            PointerSigningPostureAuditState: PointerSigningPostureAuditState,
            UpdateSigningPostureAuditState: UpdateSigningPostureAuditState,
            // W45: the Core's anchor-marker advance state — a named
            // FAILED advance is visible live, never silent.
            AnchorMarkerState: Enterprise.AnchorMarkerState);
    }

    /// <summary>Transport-core facts for the snapshot: the LAN
    /// listener's state (dormant until an operator starts it) and the
    /// failover engine's recent events. Facts only.</summary>
    private HostStateSnapshot.TransportFact BuildTransportFacts() => new(
        LanListener.IsListening, LanListener.Port, LanListener.AcceptedSessions, LanListener.RefusedHandshakes,
        Transports.Events.TakeLast(12).Select(e => new HostStateSnapshot.TransportEventFact(
            e.Kind, e.Rung, e.Detail, e.FromSessionId, e.ToSessionId)).ToList(),
        HubListener.IsListening, HubListener.Port, HubListener.AcceptedSessions, HubListener.RefusedHandshakes,
        MeshSetup.State.Stage.ToString(), MeshSetup.State.Detail);

    /// <summary>Per-scope operator roster facts from the live Slice 2
    /// store (D2 operator shape, D8 scope-filtered by construction —
    /// OperatorRoster returns one scope's records only).</summary>
    private IReadOnlyList<HostStateSnapshot.RosterScopeFact> BuildRosterFacts()
    {
        var result = new List<HostStateSnapshot.RosterScopeFact>();
        foreach (var scope in Roster.ListScopes())
        {
            var op = Roster.OperatorRoster(scope.Id);
            if (op is null) continue;
            HostStateSnapshot.RosterDeviceFact DeviceFact(EnrolledDevice d) => new(
                d.DeviceId, d.DisplayName, d.GroupId, d.GroupName, d.Scope, d.EnrolledUtc, d.Revoked, d.TransportMode, d.Sas, d.SasConfirmed);
            result.Add(new HostStateSnapshot.RosterScopeFact(
                Id: op.Scope.Id,
                Kind: op.Scope.Kind,
                Name: op.Scope.Name,
                TransportCeiling: op.Scope.HasCeiling ? op.Scope.TransportCeiling.ToList() : Array.Empty<string>(),
                CompanyAdminIds: op.CompanyAdminIds.ToList(),
                Users: op.Users.Select(u => new HostStateSnapshot.RosterUserFact(
                    u.Id, u.DisplayName, u.Kind, u.PairedByUserId, u.Suspended)).ToList(),
                UserGroups: op.UserGroups.Select(g => new HostStateSnapshot.RosterUserGroupFact(
                    g.Id, g.Name, g.MemberUserIds.ToList(), g.AdminUserIds.ToList())).ToList(),
                DeviceGroups: op.DeviceGroups.Select(g => new HostStateSnapshot.RosterDeviceGroupFact(
                    g.Id, g.Name, g.TransportSet.ToList(),
                    Roster.DeviceGroupDeviceIds(op.Scope.Id, g.Id),
                    op.Devices.Where(d => string.Equals(d.GroupId, g.Id, StringComparison.OrdinalIgnoreCase))
                        .Select(DeviceFact).ToList())).ToList(),
                Grants: op.Grants.Select(g => new HostStateSnapshot.RosterGrantFact(
                    g.UserGroupId, g.DeviceGroupId, g.Rights.ToList())).ToList()));
        }
        return result;
    }

    /// <summary>This device's D2 endpoint view, shaped for the host
    /// window's endpoint rendering: ONLY this device's own record and
    /// its receipt-derived operators. Null when this device has no
    /// enrollment record (the common case until it is itself
    /// enrolled somewhere).</summary>
    private HostStateSnapshot.EndpointFact? BuildEndpointFact()
    {
        var view = Roster.EndpointView(Identity.DeviceId);
        if (view is null) return null;
        var d = view.Device;
        return new HostStateSnapshot.EndpointFact(
            new HostStateSnapshot.RosterDeviceFact(
                d.DeviceId, d.DisplayName, d.GroupId, d.GroupName, d.Scope, d.EnrolledUtc, d.Revoked, d.TransportMode, d.Sas, d.SasConfirmed),
            view.AllowedOperators.Select(o => new HostStateSnapshot.EndpointOperatorFact(
                o.EnrollerName, o.EnrollerDeviceId, o.Scope, o.GroupName, o.EnrolledUtc)).ToList(),
            view.Receipts.Count);
    }

    private async Task PushHostStateSafelyAsync()
    {
        try
        {
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.HostState, null, null, BuildHostStateJson(), null,
                null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"host_state_push_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    /// <summary>Revoke a pairing from the laptop UI (companion window).
    /// Same discipline as gate approvals: authenticated channel only,
    /// audited, malformed payloads ignored.</summary>
    public bool TryRevokePairingFromLaptop(string? argumentsJson)
    {
        if (argumentsJson is null) return false;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var id = doc.RootElement.TryGetProperty("id", out var i) ? i.GetString() : null;
            if (string.IsNullOrWhiteSpace(id)) return false;
            var revoked = Pairings.Revoke(id);
            if (revoked) AgentEvents.RevokePairing(id); // U2 + BD-SUPP-EVENTSUB F4/F5: clear + tombstone + detach streams
            if (revoked) { try { Chat.EndThread(id); Orders.EndOrders(id); ChatSeen.EndSeen(id); } catch { } GateRequests.InvalidatePairing(id); } // W9: unpair ends the chat thread + pending gates; W120: its order cards end with it
            // BD-WIN-CORE-2/F3: revocation tears down the pairing's tunnel forwards.
            if (revoked) try { Tunnels.StopForPairing(id, "pairing revoked"); } catch { }
            // U7: revoking the pairing that owns the LIVE session
            // ends that session mid-flight and releases any input it
            // is holding — a revoked agent's fingers come off the
            // machine at the moment of revocation, not at the next
            // idle timeout.
            if (revoked && Sessions.Current is { } live && live.PairingId == id)
            {
                var endedByRevoke = Sessions.Stop();
                State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", endedByRevoke?.PairingId, endedByRevoke?.ActorAgentName, null, null, null, "session_ended:pairing_revoked", null, null));
                _ = NotifyReleaseInputsSafelyAsync();
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                revoked ? $"pairing_revoked_via_agent:{id}" : $"pairing_revoke_missed_via_agent:{id}", "SYSTEM", null));
            return revoked;
        }
        catch { return false; }
    }

    /// <summary>U7 link-loss fail-safe (Core leg): the agent channel
    /// dropped during a live session — end the session NOW (not at
    /// the idle timeout), audit it as link loss, and tear down the
    /// pairing's forwards, exactly like every other session end. The
    /// held-input release itself happens on the agent's side of the
    /// same drop (its pipe finally-block), because this Core cannot
    /// reach the desktop plane over a dead pipe.</summary>
    private void OnAgentLinkLost()
    {
        var ended = Sessions.Stop();
        if (ended is null) return;
        GateRequests.InvalidateSession(ended.Id); // W9: the dead session's pending gates die with it
        // U2: the desktop plane dying mid-session is the Windows
        // app_crash fact, origin-scoped to the session's pairing.
        AgentEvents.Publish(Shared.Sessions.AgentEventKinds.AppCrash,
            "app_crash: session agent connection lost during a live session", ended.PairingId);
        State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", ended.PairingId, ended.ActorAgentName, null, null, null, "link_loss_session_ended", null, null));
        try { Tunnels.StopForPairing(ended.PairingId); } catch { }
    }

    /// <summary>W9: the owner's host-window chat send (Addendum A).
    /// Appends an owner message to the named pairing's thread,
    /// counts it Sent in the data-flow ledger (off-device, [R4]),
    /// and audits metadata only. A send to a pairing that does not
    /// exist is refused — the thread belongs to a live pairing or
    /// it does not exist. Malformed payloads refuse quietly, never
    /// fatal (the TryApplyGateApproval posture).</summary>
    public bool ApplyChatSendFromLaptop(string? argumentsJson)
    {
        if (argumentsJson is null) return false;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var pairingId = doc.RootElement.TryGetProperty("pairingId", out var p) ? p.GetString() : null;
            var body = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() : null;
            if (string.IsNullOrWhiteSpace(pairingId) || string.IsNullOrWhiteSpace(body)) return false;
            var pairing = Pairings.List().FirstOrDefault(x => x.Id == pairingId);
            if (pairing is null) return false;
            body = body.Trim();
            if (body.Length > Shared.Sessions.AgentChatStore.MaxBodyChars) return false;
            var now = DateTimeOffset.UtcNow;
            var (_, audit) = Chat.Append(pairingId, Shared.Sessions.AgentChatStore.DirOwner, body, now.ToUnixTimeMilliseconds());
            // The ledger destination is the agent's own device; the
            // pairing record carries no device name for it, so the
            // destination stays unrecorded rather than mislabelled
            // with this host's name.
            try { Mcp.Flows?.NoteChatMessage(pairingId, pairing.AgentName, "", now); } catch { }
            Audit.Append(new AuditEntry(now, "system", pairingId, pairing.AgentName, "chat_send", null, null,
                $"chat_message_sent: direction=owner chars={audit.Chars}", "SYSTEM", null));
            AgentEvents.Publish(Shared.Sessions.AgentEventKinds.Session,
                $"chat_message_sent: pairing={pairingId} direction=owner chars={audit.Chars}", pairingId);
            return true;
        }
        catch { return false; }
    }

    /// <summary>W9: answer a host-window chat-thread request with
    /// the pairing's thread (owner channel only — bodies travel
    /// nowhere else). An ended pairing's thread is gone, so the
    /// answer is an empty thread for it, never an error.</summary>
    private async Task PushChatThreadSafelyAsync(string? argumentsJson)
    {
        try
        {
            string? pairingId = null;
            var opened = false;
            if (argumentsJson is not null)
            {
                using var doc = JsonDocument.Parse(argumentsJson);
                if (doc.RootElement.TryGetProperty("pairingId", out var p)) pairingId = p.GetString();
                // W122 / N22: "opened" is set ONLY by the host
                // window's own thread request (the owner opened
                // this thread). The Core's internal re-pushes
                // (agent post, card events) never carry it — an
                // agent posting must not mark its own messages
                // seen by the owner.
                if (doc.RootElement.TryGetProperty("opened", out var op) &&
                    op.ValueKind == JsonValueKind.True) opened = true;
            }
            if (string.IsNullOrWhiteSpace(pairingId)) return;
            var messages = Chat.Load(pairingId);
            if (opened)
            {
                // The owner has been shown the whole thread: the
                // seen cursor advances to its end and the inbox
                // index refreshes (this thread's unread clears).
                ChatSeen.Save(pairingId, messages.Count);
                _ = PushHostStateSafelyAsync();
            }
            // W120 / S13: the thread push also carries the pairing's
            // order cards, the queued count (owner messages beyond
            // the agent's read cursor), and this device's name (the
            // card's local target). Bodies and orders travel ONLY
            // on this owner channel.
            var cursor = _chatAgentCursor.TryGetValue(pairingId, out var c) ? c : 0;
            var queued = messages.Select((m, i) => (m, seq: (long)(i + 1)))
                .Count(x => x.m.Direction == Shared.Sessions.AgentChatStore.DirOwner && x.seq > cursor);
            var payload = JsonSerializer.Serialize(new
            {
                pairingId,
                messages = messages.Select((m, i) => new
                {
                    seq = i + 1,
                    atMs = m.AtMs,
                    direction = m.Direction,
                    body = m.Body,
                }).ToArray(),
                orders = Orders.Load(pairingId).Select(o => new
                {
                    id = o.Id,
                    tool = o.Tool,
                    gateClass = o.GateClass,
                    argumentsJson = o.ArgumentsJson,
                    title = o.Title,
                    targetDevice = o.TargetDevice,
                    status = o.Status,
                    resultLine = o.ResultLine,
                    createdAtMs = o.CreatedAtMs,
                }).ToArray(),
                queuedForAgent = queued,
                thisDevice = Environment.MachineName,
            });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.ChatThread, null, null, payload, null, null, null, null, null, null), _cts.Token);
        }
        catch { /* a failed thread push leaves the window on its last thread; the send path reports its own failures */ }
    }

    /// <summary>W120 / S13: validate and store one agent order
    /// proposal (the chat_order tool's Core leg). Refusals are
    /// named, never silent: unknown tool, a chat tool as subject
    /// (free text wearing a card's clothes), a tool outside the
    /// pairing's access-slider grant (an order never widens a
    /// grant), a dead pairing. A stored proposal executes NOTHING
    /// — it renders as a card in the thread and waits for the
    /// owner's answer. Audited as metadata (tool, class, target —
    /// the argument bytes live on the card, not in the chain).</summary>
    private (bool Ok, string Detail) ApplyChatOrderProposal(ChatOrderModule.Proposal proposal)
    {
        var pairing = Pairings.List().FirstOrDefault(x => x.Id == proposal.PairingId);
        if (pairing is null) return (false, "this pairing has ended, so its thread is closed.");
        var module = Tools.Find(proposal.Tool);
        if (module is null) return (false, $"unknown tool '{proposal.Tool}' — there is no such action on this device.");
        if (Shared.Sessions.ChatOrderModel.IsChatTool(proposal.Tool))
            return (false, "chat tools cannot be ordered — a message is not an action, and free text never executes.");
        if (!Shared.Sessions.ChatOrderModel.MayPropose(new HashSet<string>(pairing.Scopes), module.Descriptor))
            return (false, $"'{proposal.Tool}' needs the '{module.Descriptor.RequiredScope}' scope, which this pairing's access does not grant. An order cannot widen access — the owner changes access on the agent page, not through a card.");
        var now = DateTimeOffset.UtcNow;
        var order = new Shared.Sessions.ChatOrder(
            Id: Guid.NewGuid().ToString("N"),
            PairingId: proposal.PairingId,
            Tool: proposal.Tool,
            GateClass: module.Descriptor.GateClass,
            ArgumentsJson: proposal.Arguments.GetRawText(),
            Title: (proposal.Title ?? "").Trim(),
            TargetDevice: (proposal.TargetDevice ?? "").Trim(),
            Status: Shared.Sessions.ChatOrderStatus.Pending,
            ResultLine: null,
            CreatedAtMs: now.ToUnixTimeMilliseconds(),
            ResolvedAtMs: null);
        Orders.Append(order);
        Audit.Append(new AuditEntry(now, "system", pairing.Id, pairing.AgentName, "chat_order", null, null,
            $"chat_order_proposed: order={order.Id} tool={order.Tool} class={order.GateClass ?? "none"} target={order.TargetDevice}", "SYSTEM", null));
        _ = PushChatThreadSafelyAsync(JsonSerializer.Serialize(new { pairingId = proposal.PairingId }));
        // W122 / N22: a new pending card raises the thread's
        // waiting-on-you class in the inbox immediately.
        _ = PushHostStateSafelyAsync();
        return (true, $"order card {order.Id} is in the thread, waiting for the owner's answer. Nothing runs unless the owner taps Approve on the card.");
    }

    /// <summary>W120 / S13: the owner's answer on one order card
    /// (host window, laptop-UI channel only). The card is the gate
    /// for the order's exact bytes: Deny resolves the card and
    /// nothing runs; Deny-and-end writes approval_deny_and_end
    /// FIRST (GateSheetModel.DenyAndEndSteps), then ends the
    /// pairing's live session; Approve runs the card —
    /// ExecuteChatOrderAsync submits the exact stored bytes
    /// through the policy choke point with the order's gate class
    /// as the one-shot approval. A foreign-target card can never
    /// be approved into local execution (§8(5)).</summary>
    public void ApplyChatOrderAnswerFromLaptop(string? argumentsJson)
    {
        if (argumentsJson is null) return;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var pairingId = root.TryGetProperty("pairingId", out var p) ? p.GetString() : null;
            var orderId = root.TryGetProperty("orderId", out var o) ? o.GetString() : null;
            var answer = root.TryGetProperty("answer", out var a) ? a.GetString() : null;
            if (string.IsNullOrWhiteSpace(pairingId) || string.IsNullOrWhiteSpace(orderId) ||
                !Shared.Ipc.GateAnswers.IsAnswer(answer)) return;
            var pairing = Pairings.List().FirstOrDefault(x => x.Id == pairingId);
            var order = pairing is null ? null : Orders.Find(pairingId, orderId);
            if (pairing is null || order is null || order.Status != Shared.Sessions.ChatOrderStatus.Pending) return;
            var now = DateTimeOffset.UtcNow;
            var nowMs = now.ToUnixTimeMilliseconds();
            switch (answer)
            {
                case Shared.Ipc.GateAnswers.Deny:
                    if (Orders.TryResolve(pairingId, orderId, Shared.Sessions.ChatOrderStatus.Denied,
                            "Denied on the card — nothing ran.", nowMs))
                        Audit.Append(new AuditEntry(now, "system", pairingId, pairing.AgentName, "chat_order", null, null,
                            $"chat_order_denied: order={orderId} tool={order.Tool}", "SYSTEM", null));
                    break;
                case Shared.Ipc.GateAnswers.DenyAndEnd:
                    // Audit FIRST, teardown second — the gate's
                    // own ordering contract, kept for cards.
                    Audit.Append(new AuditEntry(now, "system", pairingId, pairing.AgentName, "chat_order", null, null,
                        $"approval_deny_and_end: order={orderId} tool={order.Tool}", "SYSTEM", null));
                    if (Orders.TryResolve(pairingId, orderId, Shared.Sessions.ChatOrderStatus.DeniedAndEnded,
                            "Denied on the card and the session ended — nothing ran.", nowMs))
                    {
                        if (Sessions.Current is { } live && string.Equals(live.PairingId, pairingId, StringComparison.Ordinal))
                        {
                            var ended = Sessions.Stop();
                            if (ended is not null) OnGateDenyAndEndTeardown(ended);
                        }
                    }
                    break;
                case Shared.Ipc.GateAnswers.Allow:
                    if (Shared.Sessions.ChatOrderModel.IsForeignTarget(order, Environment.MachineName))
                    {
                        // §8(5): an order runs only on the device
                        // it names. Approval here cannot move it.
                        Orders.TryResolve(pairingId, orderId, Shared.Sessions.ChatOrderStatus.Failed,
                            $"Not run: this order targets {order.TargetDevice}. It can only run there, under that device's own pairing and presence.", nowMs);
                        Audit.Append(new AuditEntry(now, "system", pairingId, pairing.AgentName, "chat_order", null, null,
                            $"chat_order_foreign_target_refused: order={orderId} tool={order.Tool} target={order.TargetDevice}", "SYSTEM", null));
                        break;
                    }
                    if (Orders.TryResolve(pairingId, orderId, Shared.Sessions.ChatOrderStatus.Running, "Approved — running…", nowMs))
                    {
                        Audit.Append(new AuditEntry(now, "system", pairingId, pairing.AgentName, "chat_order", null, null,
                            $"chat_order_approved: order={orderId} tool={order.Tool} class={order.GateClass ?? "none"}", "SYSTEM", null));
                        _ = ExecuteChatOrderAsync(order);
                    }
                    break;
            }
            _ = PushChatThreadSafelyAsync(JsonSerializer.Serialize(new { pairingId }));
            // W122 / N22: an answered card leaves the inbox's
            // waiting class — refresh the index with the answer.
            _ = PushHostStateSafelyAsync();
        }
        catch { /* a malformed answer resolves nothing — the card stays pending, never approved */ }
    }

    /// <summary>W120 / S13: run one approved card. The order's
    /// tool goes through McpHandler.ExecuteForPairingAsync — the
    /// same choke point as a wire call (policy, session binding,
    /// budget, audit, flow accounting) — with the order's gate
    /// class as the one-shot approved set (the card WAS the gate
    /// for these exact bytes). A tool that needs a session gets
    /// one first, started the same way the agent's own
    /// session_start starts it, so presence fires on this device
    /// in full; the session is left live for in-thread steering,
    /// with STOP beside the thread. The outcome lands back on the
    /// card (Done with the tool's own result line, or Failed with
    /// its refusal) and in the audit chain.</summary>
    private async Task ExecuteChatOrderAsync(Shared.Sessions.ChatOrder order)
    {
        string status; string line;
        try
        {
            System.Text.Json.Nodes.JsonObject args;
            try
            {
                args = System.Text.Json.Nodes.JsonNode.Parse(order.ArgumentsJson) as System.Text.Json.Nodes.JsonObject
                       ?? new System.Text.Json.Nodes.JsonObject();
            }
            catch { args = new System.Text.Json.Nodes.JsonObject(); }
            var approved = order.GateClass is { } gc
                ? new HashSet<string> { gc }
                : (IReadOnlySet<string>)new HashSet<string>();
            Shared.Tools.ToolResult result;
            if (order.Tool != "session_start" &&
                !(Sessions.Current is { } live && string.Equals(live.PairingId, order.PairingId, StringComparison.Ordinal)))
            {
                var start = await Mcp.ExecuteForPairingAsync(order.PairingId, "session_start",
                    new System.Text.Json.Nodes.JsonObject(), _cts.Token);
                if (!start.Ok)
                {
                    status = Shared.Sessions.ChatOrderStatus.Failed;
                    line = $"Not run: a session could not be started for this order ({start.UnavailableReason ?? start.ErrorClass ?? "refused"}).";
                    goto Resolve;
                }
            }
            result = await Mcp.ExecuteForPairingAsync(order.PairingId, order.Tool, args, _cts.Token, approved);
            if (result.Ok)
            {
                var text = (result.Text ?? "Done.").Trim();
                var firstLine = text.Split('\n')[0];
                status = Shared.Sessions.ChatOrderStatus.Done;
                line = firstLine.Length <= 300 ? firstLine : firstLine[..300] + "…";
            }
            else
            {
                status = Shared.Sessions.ChatOrderStatus.Failed;
                line = $"Not run: {result.UnavailableReason ?? result.ErrorClass ?? "the device refused the action."}";
            }
        }
        catch (Exception ex)
        {
            status = Shared.Sessions.ChatOrderStatus.Failed;
            line = $"Not run: {ex.GetType().Name} while running the card.";
        }
    Resolve:
        var now = DateTimeOffset.UtcNow;
        Orders.TryResolve(order.PairingId, order.Id, status, line, now.ToUnixTimeMilliseconds());
        var pairing = Pairings.List().FirstOrDefault(x => x.Id == order.PairingId);
        Audit.Append(new AuditEntry(now, "system", order.PairingId, pairing?.AgentName, "chat_order", null, null,
            $"{(status == Shared.Sessions.ChatOrderStatus.Done ? "chat_order_executed" : "chat_order_failed")}: order={order.Id} tool={order.Tool}", "SYSTEM", null));
        _ = PushChatThreadSafelyAsync(JsonSerializer.Serialize(new { pairingId = order.PairingId }));
    }

    /// <summary>W9: raise one per-action gate to the endpoint's
    /// GateSheet and resolve its answer through the broker. The
    /// request is registered BEFORE it is sent (an answer can never
    /// arrive for an unregistered id), bound to the raising pairing
    /// + session, and consumed by exactly one answer; the broker's
    /// session check reads the Core's OWN live session at answer
    /// time, so a gate whose session ended while the sheet was up
    /// resolves as no-answer. Timeout / no agent / malformed answer
    /// all return null — a NO.</summary>
    private async Task<string?> RaiseGateForSessionAsync(McpHandler.GateRaise raise, CancellationToken ct)
    {
        var request = GateRequests.Register(raise.Pairing.Id, raise.SessionId, raise.GateClass, raise.Tool,
            System.Text.Encoding.UTF8.GetBytes(raise.ArgumentsJson), raise.FromChat, DateTimeOffset.UtcNow);
        Shared.Ipc.IpcMessage? answerMsg;
        try { answerMsg = await Ipc.RequestGateAnswerAsync(request, Shared.Ipc.GateRequestBroker.DefaultTimeout, ct); }
        catch { answerMsg = null; }
        if (answerMsg is null)
        {
            GateRequests.Abandon(request.Id);
            return null;
        }
        var parsed = Shared.Ipc.GateRequestPayload.ParseAnswer(answerMsg.ArgumentsJson, answerMsg.RequestId);
        if (parsed is null) { GateRequests.Abandon(request.Id); return null; }
        var resolution = GateRequests.TryAnswer(parsed.Value.RequestId, parsed.Value.Answer,
            Sessions.Current?.Id, DateTimeOffset.UtcNow, out _, out var accepted);
        return resolution == Shared.Ipc.GateResolution.Answered ? accepted : null;
    }

    /// <summary>W9: teardown for a gate Deny-and-end. The handler has
    /// ALREADY written approval_deny_and_end and stopped the session
    /// (the audit-first order); this host leg does the rest of the
    /// session-end work: pending gates for the dead session die with
    /// it, the acting-agent state clears, tunnels stop, held inputs
    /// release, and the presence layer gets its final directive.</summary>
    private void OnGateDenyAndEndTeardown(SessionRecord ended)
    {
        GateRequests.InvalidateSession(ended.Id);
        State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
        try { Tunnels.StopForPairing(ended.PairingId, "gate deny-and-end"); } catch { }
        _ = NotifyReleaseInputsSafelyAsync();
        _ = PushPresenceSafelyAsync(null, State.StopInForce);
    }

    /// <summary>U7: end the live session because its pairing was
    /// revoked through the admin tool path (the laptop-UI path,
    /// TryRevokePairingFromLaptop, carries its own copy of this).
    /// Callback for PairingAdminModule.</summary>
    private void OnPairingRevokedSessionEnd(SessionRecord ended)
    {
        GateRequests.InvalidatePairing(ended.PairingId); // W9: a revoked pairing's pending gates die with it
        AgentEvents.RevokePairing(ended.PairingId); // U2 + F4/F5: a revoked pairing keeps no event rights, streams end
        State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", ended.PairingId, ended.ActorAgentName, null, null, null, "session_ended:pairing_revoked", null, null));
        try { Tunnels.StopForPairing(ended.PairingId, "pairing revoked"); } catch { }
        _ = NotifyReleaseInputsSafelyAsync();
    }

    /// <summary>U7: order the session agent to release every held
    /// key/button. Fire-and-forget but OBSERVED, like the presence
    /// push: a failed send is audited. When the pipe is down the
    /// send no-ops — the agent's own disconnect trigger has already
    /// released in that case, so no path leaves input held.</summary>
    private async Task NotifyReleaseInputsSafelyAsync()
    {
        try
        {
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.ReleaseInputs, null, null, null, null, null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"release_inputs_notify_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    /// <summary>Mint a pairing code from the laptop UI and send it back
    /// for display — once, to the person at the keyboard. Scopes are
    /// bound at mint time from the chosen preset (C1): the exchanging
    /// agent can never widen them.</summary>
    private async Task PushPairingCodeSafelyAsync(string? argumentsJson)
    {
        try
        {
            string agentName = "Agent";
            // BD-WIN-CORE-1 F1: an absent preset mints the LEAST
            // privilege (look_only), never full_control by default.
            string preset = "look_only";
            // W97 / S09(b): the Pair card's connection-mode choice,
            // bound to the code at mint like the scopes (C1).
            // Absent = AUTO (the default). Present but invalid =
            // the mint REFUSES — never a silent widening to AUTO.
            ConnectionPathSetting? connection = null;
            if (argumentsJson is not null)
            {
                using var doc = JsonDocument.Parse(argumentsJson);
                if (doc.RootElement.TryGetProperty("agentName", out var n) && n.GetString() is { Length: > 0 } name)
                    agentName = name;
                if (doc.RootElement.TryGetProperty("preset", out var p) && p.GetString() is { Length: > 0 } pr)
                    preset = pr;
                if (doc.RootElement.TryGetProperty("connection", out var c) && c.ValueKind == JsonValueKind.Object)
                {
                    var parsed = ConnectionPathPolicy.Parse(
                        JsonStr(c, "mode"), JsonStrArray(c, "allowedRungs"), JsonStr(c, "pinnedRung"));
                    var refusal = parsed is null
                        ? "unknown connection mode — refused"
                        : ConnectionPathPolicy.Validate(parsed);
                    if (refusal is not null)
                    {
                        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                            $"pairing_code_mint_refused_via_agent:{agentName}:{refusal}", "SYSTEM", null));
                        return;
                    }
                    connection = parsed;
                }
            }
            var ttl = TimeSpan.FromMinutes(10);
            var code = Pairings.CreatePairingCode(agentName, ttl, Scopes.Preset(preset), connection);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"pairing_code_minted_via_agent:{agentName}:{preset}:{ConnectionPathPolicy.Describe(connection)}", "SYSTEM", null));
            var payload = JsonSerializer.Serialize(new
            {
                code,
                expiresUtc = DateTimeOffset.UtcNow + ttl,
                agentName,
                preset,
            });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.PairingCode, null, null, payload, null,
                null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"pairing_code_mint_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    // ---- W79 / S08: pairing grant changes from the access surface --
    // Reached ONLY from the authenticated agent-IPC channel above
    // (a consent kind: the person at the keyboard is the consent).
    // Every outcome is audited — an applied change names the old
    // and new grant sets; a refusal names its reason. The store
    // (PairingService.UpdateScopes) owns the validation: unknown
    // grants refuse, and ADDING the elevation class (admin,
    // unlock, background_kit_admin — W107) refuses without the
    // owner's separate confirmation carried in the payload.

    public (bool Ok, string Detail) ApplyPairingAccess(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var id = JsonStr(root, "id") ?? "";
            var proposed = new HashSet<string>(JsonStrArray(root, "scopes"));
            var elevationConfirmed = JsonBool(root, "elevationConfirmed");
            var pairing = Pairings.List().FirstOrDefault(p => p.Id == id);
            var (ok, detail, oldScopes) = Pairings.UpdateScopes(id, proposed, elevationConfirmed);
            var name = pairing?.AgentName ?? id;
            if (ok)
            {
                string Fmt(IReadOnlySet<string> s) => s.Count == 0 ? "(none)" : string.Join(",", s.OrderBy(x => x));
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", id, name, null, null, null,
                    $"pairing_access_via_agent:{name}:grants {Fmt(oldScopes!)} -> {Fmt(proposed)}", "SYSTEM", null));
                return (true, $"grants updated for {name}");
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", id, name, null, null, null,
                $"pairing_access_refused_via_agent:{name}:{detail}", "SYSTEM", null));
            return (false, detail);
        }
        catch (Exception ex) { return (false, $"malformed pairing-access payload ({ex.GetType().Name})"); }
    }

    private async Task ApplyPairingAccessSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyPairingAccess(argumentsJson);
        await PushActionResultSafelyAsync("pairing_access", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    // ---- W97 / S09(b): pairing connection-path changes from the
    // agent card — the same consent/audit pattern as pairing_access
    // above. Reached ONLY from the authenticated agent-IPC channel
    // (a consent kind). Every outcome is audited: an applied change
    // names the old and new settings in plain language; a refusal
    // names its reason. The store (PairingService.UpdateConnectionPath)
    // owns the validation.

    public (bool Ok, string Detail) ApplyPairingConnection(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var id = JsonStr(root, "id") ?? "";
            var proposed = ConnectionPathPolicy.Parse(
                JsonStr(root, "mode"), JsonStrArray(root, "allowedRungs"), JsonStr(root, "pinnedRung"));
            var pairing = Pairings.List().FirstOrDefault(p => p.Id == id);
            var name = pairing?.AgentName ?? id;
            if (proposed is null)
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", id, name, null, null, null,
                    $"pairing_connection_refused_via_agent:{name}:unknown connection mode — refused", "SYSTEM", null));
                return (false, "unknown connection mode — refused");
            }
            var (ok, detail, oldSetting) = Pairings.UpdateConnectionPath(id, proposed);
            if (ok)
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", id, name, null, null, null,
                    $"pairing_connection_via_agent:{name}:{ConnectionPathPolicy.Describe(oldSetting)} -> {ConnectionPathPolicy.Describe(proposed)}", "SYSTEM", null));
                return (true, $"connection path updated for {name}");
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", id, name, null, null, null,
                $"pairing_connection_refused_via_agent:{name}:{detail}", "SYSTEM", null));
            return (false, detail);
        }
        catch (Exception ex) { return (false, $"malformed pairing-connection payload ({ex.GetType().Name})"); }
    }

    private async Task ApplyPairingConnectionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyPairingConnection(argumentsJson);
        await PushActionResultSafelyAsync("pairing_connection", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    // ---- Slice 2/3 host-window actions (Block A wiring) -------------
    // Every method below is reached ONLY from the authenticated
    // agent-IPC event above (the laptop UI), exactly like gate
    // approvals and the vault. Malformed payloads refuse quietly
    // (false + detail), never throw, never partially mutate: the
    // stores' own guard refusals are the semantics.

    private static string? JsonStr(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

    private static bool JsonBool(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static string[] JsonStrArray(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToArray()
            : Array.Empty<string>();

    private static bool JsonHas(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out _);

    /// <summary>One Slice 2 roster act from the host window. The
    /// store's guards ARE the authorization model (AI never admin,
    /// last-admin, step-up, cross-scope wall) — this method routes
    /// and audits, it does not re-decide.</summary>
    public (bool Ok, string Detail) ApplyRosterAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var action = JsonStr(root, "action") ?? "";
            (bool, string) result = action switch
            {
                "create_scope" => Roster.CreateScope(
                        JsonStr(root, "id") ?? "", JsonStr(root, "kind") ?? "", JsonStr(root, "name") ?? "",
                        JsonHas(root, "transportCeiling") ? JsonStrArray(root, "transportCeiling") : null) is { } scope
                    ? (true, $"scope {scope.Id} created")
                    : (false, "scope creation refused (duplicate id, bad kind, or bad ceiling)"),
                "create_user" => Roster.CreateUser(
                        JsonStr(root, "id") ?? "", JsonStr(root, "scopeId") ?? "", JsonStr(root, "displayName") ?? "",
                        JsonStr(root, "kind") ?? "", JsonStr(root, "pairedByUserId")) is { } user
                    ? (true, $"user {user.Id} created in {user.ScopeId}")
                    : (false, "user creation refused (unknown scope/kind, duplicate, or AI without a human owner in the same scope)"),
                "create_user_group" => Roster.CreateUserGroup(
                        JsonStr(root, "id") ?? "", JsonStr(root, "scopeId") ?? "", JsonStr(root, "name") ?? "",
                        JsonStrArray(root, "members"), JsonStrArray(root, "admins")) is { } ug
                    ? (true, $"user group {ug.Id} created")
                    : (false, "user group creation refused (unknown scope/member, duplicate, or AI admin)"),
                "create_device_group" => Roster.CreateDeviceGroup(
                        JsonStr(root, "id") ?? "", JsonStr(root, "scopeId") ?? "", JsonStr(root, "name") ?? "",
                        JsonHas(root, "transportSet") ? JsonStrArray(root, "transportSet") : null) is { } dg
                    ? (true, $"device group {dg.Id} created")
                    : (false, "device group creation refused (unknown scope, duplicate/tombstoned id, or non-rung transport)"),
                // BD-WIN-CORE-1 F2: grant creation goes through
                // the actor-gated overload whenever an actor is
                // named OR the scope is administered (has company
                // admins). The actor-less overload remains ONLY for
                // bootstrap construction — a scope with no admins
                // yet, where no actor could pass the gate and the
                // act rides the OS-verified console channel (F1) as
                // the owner's own setup act, audited as such below.
                // Once a scope has admins, an actor-less grant is
                // refused, never silently trusted.
                "add_grant" => (JsonStr(root, "actorUserId") is { } grantActor
                    ? Roster.AddGrant(
                        JsonStr(root, "scopeId") ?? "", JsonStr(root, "userGroupId") ?? "",
                        JsonStr(root, "deviceGroupId") ?? "", JsonStrArray(root, "rights"), grantActor)
                    : Roster.CompanyAdmins(JsonStr(root, "scopeId") ?? "").Count == 0
                        ? Roster.AddGrant(
                            JsonStr(root, "scopeId") ?? "", JsonStr(root, "userGroupId") ?? "",
                            JsonStr(root, "deviceGroupId") ?? "", JsonStrArray(root, "rights"))
                        : null) is { } grant
                    ? (true, $"grant {grant.UserGroupId} → {grant.DeviceGroupId} recorded")
                    : (false, "grant refused (unknown group in that scope, rights outside use/enroll/admin, or — in an administered scope — no actor who holds admin authority was named)"),
                // BD-WIN-CORE-1 F2: seating a company admin now
                // requires an actor who is already a live company
                // admin of the scope — except the bootstrap case
                // where the scope has no admins yet (first seating
                // by the owner at the laptop).
                "add_company_admin" => AddCompanyAdminFromLaptop(root),
                "remove_user" => RemoveUserFromLaptop(root),
                // Transport-set editing (Block C part 1, D31/D32):
                // changing a group's SET is a group-admin act (the
                // store's guard decides); the company ceiling caps
                // every resolution; a per-device override narrows or
                // pins within the resolved set and is rejected whole
                // when a pin falls outside it. Refusals surface here
                // as refusals — never a silent no-op.
                "set_group_transports" => Roster.SetGroupTransports(
                        JsonStr(root, "scopeId") ?? "", JsonStr(root, "groupId") ?? "",
                        JsonStrArray(root, "transportSet"), JsonStr(root, "actorUserId") ?? "")
                    ? (true, "transport set updated")
                    : (false, "transport set change refused (changing the set is a group-admin act; the set must name valid rungs)"),
                // BD-WIN-CORE-1 F2: the ceiling is a company-admin
                // act — the payload must name an actor who is a live
                // company admin of the scope.
                "set_scope_ceiling" => (JsonStr(root, "actorUserId") is { } ceilingActor &&
                        Roster.IsCompanyAdmin(JsonStr(root, "scopeId") ?? "", ceilingActor) &&
                        Roster.SetScopeTransportCeiling(
                            JsonStr(root, "scopeId") ?? "",
                            JsonHas(root, "transportCeiling") ? JsonStrArray(root, "transportCeiling") : null))
                    ? (true, "scope transport ceiling updated")
                    : (false, "ceiling change refused (actor is not a live company admin of the scope, unknown scope, or non-rung transport)"),
                "update_device_transports" => Roster.UpdateDeviceTransportPolicy(
                        JsonStr(root, "deviceId") ?? "", JsonStr(root, "transportMode") ?? "inherit",
                        JsonHas(root, "allowedTransports") ? JsonStrArray(root, "allowedTransports") : null)
                    ? (true, "device transport policy updated")
                    : (false, "device transport change refused (a pin must stay within the device's resolved set; pins belong to manual mode)"),
                _ => (false, $"unknown roster action: {action}"),
            };
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"roster_action_via_agent:{action}:{(result.Item1 ? "ok" : "refused")}", "SYSTEM", null));
            return result;
        }
        catch (Exception ex) { return (false, $"malformed roster payload ({ex.GetType().Name})"); }
    }

    private (bool, string) AddCompanyAdminFromLaptop(JsonElement root)
    {
        var scopeId = JsonStr(root, "scopeId") ?? "";
        var actor = JsonStr(root, "actorUserId");
        var existing = Roster.CompanyAdmins(scopeId);
        if (existing.Count > 0 && (actor is null || !Roster.IsCompanyAdmin(scopeId, actor)))
            return (false, "admin seating refused (actor is not a live company admin of the scope)");
        return Roster.AddCompanyAdmin(scopeId, JsonStr(root, "userId") ?? "")
            ? (true, "company admin seated")
            : (false, "admin seating refused (non-company scope, unknown/suspended user, or AI)");
    }

    /// <summary>The D14 offboarding fire, from the laptop UI. The
    /// window previews the blast list first (RosterOffboardPreview);
    /// this is the firing call and returns what actually fired.</summary>
    private (bool, string) RemoveUserFromLaptop(JsonElement root)
    {
        var blast = Roster.RemoveUser(
            JsonStr(root, "scopeId") ?? "", JsonStr(root, "userId") ?? "",
            JsonStr(root, "actorUserId") ?? "", JsonBool(root, "stepUp"));
        return blast is null
            ? (false, "removal refused (personal scope, cross-scope, actor not a live company admin, last-admin guard, or step-up required)")
            : (true, $"user {blast.UserId} removed: {blast.UserGroupSeatIds.Count} group seat(s), " +
                     $"company admin seat: {blast.CompanyAdminSeat}, {blast.MintedEnrollmentDeviceIds.Count} minted enrollment(s) revoked, " +
                     $"{blast.OwnedAiUserIds.Count} owned AI pairing(s) suspended");
    }

    /// <summary>The D14 blast list for the window's pre-fire display,
    /// shaped as JSON (ids/counts only). Null when the scope/user does
    /// not exist — the window shows the refusal, never a stale list.</summary>
    public string? BuildOffboardBlastJson(string? argumentsJson)
    {
        if (argumentsJson is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var blast = Roster.PreviewRemoveUser(
                JsonStr(doc.RootElement, "scopeId") ?? "", JsonStr(doc.RootElement, "userId") ?? "");
            return blast is null ? null : HostStateSnapshot.ShapeBlastJson(blast);
        }
        catch { return null; }
    }

    /// <summary>One Slice 3 session act from the host window. The
    /// "accept" sub-action is the endpoint-local UI act of the
    /// 2026-11-19 ruling: it is honored ONLY with
    /// SessionAcceptOrigin.EndpointLocal, because this channel IS the
    /// endpoint's local UI. A payload explicitly claiming the
    /// initiating-channel origin refuses — channel accepts never
    /// count, through any path.</summary>
    public (bool Ok, string Detail) ApplySessionAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var action = JsonStr(root, "action") ?? "";
            var id = JsonStr(root, "sessionId") ?? "";
            var actor = JsonStr(root, "actorUserId");
            (bool, string) result = action switch
            {
                "create" => HumanSessions.CreateSession(
                        JsonStr(root, "scopeId") ?? "", JsonStr(root, "hostDeviceId") ?? "",
                        JsonStr(root, "initiatorUserId") ?? "", JsonStr(root, "kind") ?? "",
                        JsonStr(root, "transportRung") ?? "", JsonStr(root, "recording") ?? "none",
                        JsonStr(root, "recordingRef")) is { } created
                    ? (true, $"session {created.Id} requested")
                    : (false, "session creation refused (unknown scope/device/initiator, device not filed in this scope, bad kind/rung, or remote recording ref)"),
                "accept" => AcceptFromLaptop(root, id),
                "start" => HumanSessions.StartSession(id, actor)
                    ? (true, "session started") : (false, "start refused (consent/grant/transport/offboarding gate)"),
                "pause" => HumanSessions.PauseSession(id, actor)
                    ? (true, "session paused") : (false, "pause refused"),
                "resume" => HumanSessions.ResumeSession(id, actor)
                    ? (true, "session resumed") : (false, "resume refused"),
                "end" => HumanSessions.EndSession(id, actor)
                    ? (true, "session ended") : (false, "end refused"),
                "stop" => actor is not null && HumanSessions.StopSession(id, actor)
                    ? (true, "session stopped (host STOP)") : (false, "STOP refused (actor must be host-side)"),
                // U4: the owner's resume for a tripwire-paused AGENT
                // session. This channel is the endpoint-local host
                // window by construction — the agent itself has no
                // resume path, so a tripped session stays paused
                // until the person at the host clears it.
                "resume_agent_session" => ResumeAgentSession(),
                "add_participant" => HumanSessions.AddParticipant(id, JsonStr(root, "userId") ?? "", JsonStr(root, "role") ?? "watcher", actor ?? "")
                    ? (true, "participant added") : (false, "add refused (host role is never assignable; actor must be initiator/host-side)"),
                "remove_participant" => HumanSessions.RemoveParticipant(id, JsonStr(root, "userId") ?? "", actor ?? "")
                    ? (true, "participant removed") : (false, "remove refused (host-side actors only)"),
                "grant_floor" => HumanSessions.GrantFloor(id, JsonStr(root, "userId") ?? "", actor ?? "")
                    ? (true, "floor granted") : (false, "floor grant refused (host-side actors only)"),
                "take_floor" => HumanSessions.TakeFloorBack(id, actor ?? "")
                    ? (true, "floor taken back to host") : (false, "take-back refused"),
                "set_watch_only" => HumanSessions.SetWatchOnly(id, JsonStr(root, "userId") ?? "", actor ?? "")
                    ? (true, "participant set watch-only") : (false, "watch-only refused"),
                "set_recording" => HumanSessions.SetRecording(id, JsonStr(root, "recording") ?? "none", JsonStr(root, "recordingRef"), actor)
                    ? (true, "recording updated") : (false, "recording change refused (turning recording on is a host-side act; refs must be local)"),
                _ => (false, $"unknown session action: {action}"),
            };
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"session_action_via_agent:{action}:{(result.Item1 ? "ok" : "refused")}", "SYSTEM", null));
            return result;
        }
        catch (Exception ex) { return (false, $"malformed session payload ({ex.GetType().Name})"); }
    }

    /// <summary>U4 owner resume: clear a budget/SCAM tripwire pause
    /// on the live agent session. Budget counts stand (the budget is
    /// per session; resuming accepts the shown state, it is not a
    /// fresh allowance).</summary>
    private (bool, string) ResumeAgentSession()
    {
        if (Sessions.Current is not { } cur) return (false, "no live agent session to resume");
        var cleared = Sessions.Resume();
        if (cleared is null) return (false, "the live agent session is not paused");
        Mcp.Budgets.Resume(cur.Id);
        State.LastNarration = "Resumed by the owner";
        return (true, $"agent session resumed by the owner (was paused: {cleared})");
    }

    private (bool, string) AcceptFromLaptop(JsonElement root, string sessionId)
    {
        // The ruling, enforced at the surface: an explicit
        // initiating-channel origin refuses even here. Absent or
        // endpoint_local is the local UI's own act — this channel is
        // the endpoint-local UI by construction (authenticated pipe,
        // laptop window), the same trust basis as gate approvals.
        var origin = JsonStr(root, "origin");
        if (origin is not null && origin != SessionService.AcceptOriginEndpointLocal)
            return (false, "channel accepts never count (2026-11-19 endpoint-local ruling)");
        var acceptBy = JsonStr(root, "acceptByUserId") ?? JsonStr(root, "actorUserId") ?? "";
        return HumanSessions.AcceptSessionLocal(sessionId, acceptBy, HumanSessions.LocalAcceptCapability)
            ? (true, "accepted at this device, locally")
            : (false, "accept refused (unknown/ended/unattended session, or acceptor not a live human of the scope)");
    }

    /// <summary>Redeem an enrollment code for THIS device from the
    /// host window — the live mint→redeem round trip. The Core
    /// presents its own Slice 1 identity (DeviceId is the fingerprint
    /// of its public key; the store's binding check proves it). When
    /// the payload names the roster scope + minter, the minted-by
    /// attribution is recorded so D14 offboarding can revoke it.</summary>
    public (bool Ok, string Detail) ApplyEnrollmentRedeem(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var displayName = JsonStr(root, "displayName") is { Length: > 0 } dn ? dn : Environment.MachineName;
            var enrolled = Enrollments.Redeem(JsonStr(root, "code"),
                new EnrollingDevice(Identity.DeviceId, Identity.PublicKeyBase64, displayName));
            if (enrolled is null)
            {
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                    "enrollment_redeem_via_agent:refused", "SYSTEM", null));
                return (false, "redeem refused (unknown/expired/consumed code, or this device is revoked)");
            }
            var rosterScopeId = JsonStr(root, "rosterScopeId");
            var mintedBy = JsonStr(root, "mintedByUserId");
            if (rosterScopeId is not null && mintedBy is not null)
                Roster.RecordMintedEnrollment(rosterScopeId, mintedBy, enrolled.DeviceId);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"enrollment_redeemed_via_agent:{enrolled.GroupId}:{enrolled.Scope}", "SYSTEM", null));
            return (true, $"this device enrolled into {enrolled.GroupName} ({enrolled.GroupId}), scope {enrolled.Scope}");
        }
        catch (Exception ex) { return (false, $"malformed redeem payload ({ex.GetType().Name})"); }
    }

    /// <summary>One transport-core act from the host window (Block C
    /// part 1). Start walks the device's resolved transport set via
    /// the failover engine — the session record's rung is the rung
    /// that actually carried it; an address in the payload is
    /// connect-by-address on the `lan` rung (D19). Re-establish ends
    /// the old session (transport_failover) and starts a new one on
    /// the next rung — a reconnect, linked by events. The LAN
    /// listener opens ONLY on the operator's start act (dormancy,
    /// D29). Discovery browse/announce ride the same channel;
    /// discovery grants no trust (D20).</summary>
    public async Task<(bool Ok, string Detail)> ApplyTransportAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var action = JsonStr(root, "action") ?? "";
            (bool, string) result;
            switch (action)
            {
                case "start":
                {
                    var address = JsonStr(root, "address");
                    var targets = new Dictionary<string, TransportTarget>();
                    var hostDeviceId = JsonStr(root, "hostDeviceId") ?? "";
                    if (!string.IsNullOrWhiteSpace(address))
                        targets["lan"] = new TransportTarget(hostDeviceId, address.Trim());
                    // Block C part 3: per-rung targets — the hub
                    // target is the peer's tailnet IP on the ACP
                    // hub mesh; the mesh target its vendor tailnet
                    // IP. Each rung validates its own addressing.
                    var hubAddress = JsonStr(root, "hubAddress");
                    if (!string.IsNullOrWhiteSpace(hubAddress))
                        targets["hub"] = new TransportTarget(hostDeviceId, hubAddress.Trim());
                    var meshAddress = JsonStr(root, "meshAddress");
                    if (!string.IsNullOrWhiteSpace(meshAddress))
                        targets["mesh"] = new TransportTarget(hostDeviceId, meshAddress.Trim());
                    // The window sends "manualPins": null for "no pin" —
                    // the property is present but not an array. That must
                    // mean NO pin (null), never an empty pin list: the
                    // engine refuses an empty pin set wholesale, so the
                    // null shape refused every unpinned window start
                    // (live-proof find, 2026-11-19; regression in
                    // TransportWiringTests).
                    var pinsRaw = JsonHas(root, "manualPins") ? JsonStrArray(root, "manualPins") : null;
                    var pins = pinsRaw is { Length: > 0 } ? pinsRaw : null;
                    var session = await Transports.StartSessionAsync(
                        JsonStr(root, "scopeId") ?? "", hostDeviceId,
                        JsonStr(root, "initiatorUserId") ?? "", JsonStr(root, "kind") ?? "unattended",
                        targets, JsonStr(root, "recording") ?? "none", pins, _cts.Token);
                    result = session is not null
                        ? (true, $"session {session.Id} started over {session.TransportRung}")
                        : (false, "transport start failed — " + LastTransportEventDetail());
                    break;
                }
                case "reestablish":
                {
                    var sessionId = JsonStr(root, "sessionId") ?? "";
                    var address = JsonStr(root, "address");
                    var targets = new Dictionary<string, TransportTarget>();
                    if (!string.IsNullOrWhiteSpace(address))
                    {
                        var hostDeviceId = HumanSessions.GetSession(sessionId)?.HostDeviceId ?? "";
                        targets["lan"] = new TransportTarget(hostDeviceId, address.Trim());
                    }
                    var hubAddress = JsonStr(root, "hubAddress");
                    if (!string.IsNullOrWhiteSpace(hubAddress))
                    {
                        var hostDeviceId = HumanSessions.GetSession(sessionId)?.HostDeviceId ?? "";
                        targets["hub"] = new TransportTarget(hostDeviceId, hubAddress.Trim());
                    }
                    var meshAddress = JsonStr(root, "meshAddress");
                    if (!string.IsNullOrWhiteSpace(meshAddress))
                    {
                        var hostDeviceId = HumanSessions.GetSession(sessionId)?.HostDeviceId ?? "";
                        targets["mesh"] = new TransportTarget(hostDeviceId, meshAddress.Trim());
                    }
                    var next = await Transports.ReestablishAsync(sessionId, targets, _cts.Token);
                    result = next is not null
                        ? (true, $"re-established as session {next.Id} over {next.TransportRung} (the previous session ended: transport failover)")
                        : (false, "re-establish failed — " + LastTransportEventDetail());
                    break;
                }
                case "start_lan_listener":
                {
                    if (LanListener.IsListening) { result = (true, $"LAN listener already listening on port {LanListener.Port}"); break; }
                    LanListener.Start(IPAddress.Any);
                    result = (true, $"LAN listener listening on port {LanListener.Port} — peers must still prove possession of an enrolled device key");
                    break;
                }
                case "stop_lan_listener":
                    LanListener.Stop();
                    result = (true, "LAN listener stopped — the rung is dormant again");
                    break;
                case "start_hub_listener":
                {
                    // The hub host side: the SAME enrollment
                    // handshake, bound to this device's mesh
                    // address (its tailnet IP on the ACP hub).
                    // Mesh membership never admits — the handshake
                    // does. Dormant until this act.
                    var bind = JsonStr(root, "address");
                    if (string.IsNullOrWhiteSpace(bind) || !IPAddress.TryParse(bind.Trim(), out var bindIp))
                    { result = (false, "hub listener needs this device's mesh (tailnet) address to bind"); break; }
                    if (!MeshAddress.IsTailnetAddress(bind.Trim()))
                    { result = (false, "hub listener binds only a tailnet (100.64.0.0/10) address — refusing to expose the hub host side on a LAN address"); break; }
                    if (HubListener.IsListening) { result = (true, $"hub listener already listening on port {HubListener.Port}"); break; }
                    HubListener.Start(bindIp);
                    result = (true, $"hub listener listening on {bind.Trim()}:{HubListener.Port} — mesh membership alone admits nobody; peers must prove possession of an enrolled device key");
                    break;
                }
                case "stop_hub_listener":
                    HubListener.Stop();
                    result = (true, "hub listener stopped — the rung is dormant again");
                    break;
                case "mesh_preflight":
                {
                    // D4 setup, ACP's side (Block C part 3): role is
                    // operator (this Core is an operator install);
                    // every T2 condition is checked and the flow
                    // stops AT the sign-in boundary.
                    var st = MeshSetup.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator);
                    result = (st.Stage != MeshSetupStage.Refused,
                        $"mesh setup: {st.Stage} — {st.Detail}");
                    break;
                }
                case "mesh_set_credential":
                {
                    var scopes = JsonHas(root, "scopes") ? JsonStrArray(root, "scopes") ?? Array.Empty<string>() : Array.Empty<string>();
                    var verdict = MeshSetup.Broker.SetCredential(
                        JsonStr(root, "clientId") ?? "", JsonStr(root, "clientSecret") ?? "", scopes);
                    result = (verdict.Ok, "mesh credential: " + verdict.Detail);
                    break;
                }
                case "mesh_finish":
                {
                    // The sign-in moment itself happened on
                    // Tailscale's own page, hosted by the person at
                    // this window; the window asserts only its
                    // completion over the authenticated IPC channel
                    // (the same trust shape as gate approvals). ACP
                    // receives no credential from that page, ever.
                    var scopeId = JsonStr(root, "scopeId") ?? "";
                    var mapping = BuildTailnetMapping(scopeId, JsonStr(root, "sessionPort"));
                    if (mapping is null) { result = (false, "mesh setup: unknown scope for the D12 policy mapping"); break; }
                    var completed = root.TryGetProperty("signInCompleted", out var sic) && sic.ValueKind == JsonValueKind.True;
                    var st = await MeshSetup.CompleteAfterSignInAsync(
                        () => Task.FromResult(completed), mapping, DateTimeOffset.UtcNow, _cts.Token);
                    result = (st.Stage == MeshSetupStage.Ready, $"mesh setup: {st.Stage} — {st.Detail}");
                    break;
                }
                case "announce_discovery":
                {
                    var own = Enrollments.List().FirstOrDefault(
                        d => string.Equals(d.DeviceId, Identity.DeviceId, StringComparison.OrdinalIgnoreCase));
                    var announcement = DiscoveryAnnouncement.ForDevice(
                        Identity.DeviceId, own?.DisplayName ?? Environment.MachineName, own is not null && !own.Revoked);
                    if (announcement is null) { result = (false, "announce refused (this device's name is not announceable)"); break; }
                    await new DiscoveryService().AnnounceAsync(announcement, ct: _cts.Token);
                    result = (true, "announced on the local network (device-id hash, name, enrollment state only)");
                    break;
                }
                case "browse_discovery":
                {
                    var found = await BrowseDiscoveryAsync(root);
                    await PushDiscoveryResultSafelyAsync(found);
                    result = (true, $"browse complete: {found.Count} device(s) heard — unpaired devices are available to enroll; discovery grants no control");
                    break;
                }
                default:
                    result = (false, $"unknown transport action: {action}");
                    break;
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"transport_action_via_agent:{action}:{(result.Item1 ? "ok" : "refused")}", "SYSTEM", null));
            return result;
        }
        catch (Exception ex) { return (false, $"transport action failed ({ex.GetType().Name}: {ex.Message})"); }
    }

    private string LastTransportEventDetail() =>
        Transports.Events.LastOrDefault() is { } e ? $"{e.Kind}: {e.Detail}" : "no engine events";

    /// <summary>The D12 mapping for one scope, derived from the
    /// live roster: user groups → ACL groups (their member ids),
    /// device groups → tags, grants carrying the `enroll` right →
    /// tagOwners, grants carrying `use` → ACL accepts on the ACP
    /// session port. Names pass through AclBuilder's validators —
    /// a roster name that cannot be a tailnet name refuses the
    /// policy build, by design.</summary>
    private TailnetMapping? BuildTailnetMapping(string scopeId, string? sessionPort)
    {
        if (Roster.ListScopes().All(s => s.Id != scopeId)) return null;
        var userGroups = Roster.ListUserGroups(scopeId);
        var deviceGroups = Roster.ListDeviceGroups(scopeId);
        var grants = Roster.ListGrants(scopeId);
        var ugName = userGroups.ToDictionary(g => g.Id, g => g.Name);
        var dgName = deviceGroups.ToDictionary(g => g.Id, g => g.Name);
        var port = string.IsNullOrWhiteSpace(sessionPort) ? LanProtocol.DefaultPort.ToString() : sessionPort.Trim();
        return new TailnetMapping(
            UserGroups: userGroups.ToDictionary(g => g.Name, g => (IReadOnlyList<string>)g.MemberUserIds.ToList()),
            DeviceGroups: deviceGroups.Select(g => g.Name).ToList(),
            EnrollRights: deviceGroups.ToDictionary(
                dg => dg.Name,
                dg => (IReadOnlyList<string>)grants
                    .Where(gr => gr.DeviceGroupId == dg.Id && gr.Rights.Contains("enroll") && ugName.ContainsKey(gr.UserGroupId))
                    .Select(gr => ugName[gr.UserGroupId]).Distinct().ToList()),
            Grants: grants
                .Where(gr => gr.Rights.Contains("use") && ugName.ContainsKey(gr.UserGroupId) && dgName.ContainsKey(gr.DeviceGroupId))
                .Select(gr => new TailnetGrant(ugName[gr.UserGroupId], dgName[gr.DeviceGroupId], new[] { port }))
                .ToList());
    }

    /// <summary>One bounded discovery browse (D19/D20): listen for
    /// announcements, classify against this install's enrolled
    /// device ids (matched by hash). A window, never a scan.</summary>
    public async Task<IReadOnlyList<DiscoveredDevice>> BrowseDiscoveryAsync(JsonElement root)
    {
        var windowMs = root.ValueKind == JsonValueKind.Object &&
                       root.TryGetProperty("windowMs", out var w) && w.ValueKind == JsonValueKind.Number
            ? Math.Clamp(w.GetInt32(), 500, 10_000) : 3_000;
        var svc = new DiscoveryService(Enrollments.List().Select(d => d.DeviceId));
        return await svc.BrowseAsync(TimeSpan.FromMilliseconds(windowMs), ct: _cts.Token);
    }

    private async Task PushDiscoveryResultSafelyAsync(IReadOnlyList<DiscoveredDevice> found)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                devices = found.Select(d => new
                {
                    name = d.Announcement.DisplayName,
                    hash = d.Announcement.DeviceIdHash,
                    state = d.Announcement.EnrollmentState,
                    knownPeer = d.IsKnownPeer,
                    availableToEnroll = d.AvailableToEnroll,
                }).ToArray(),
            });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.DiscoveryResult, null, null, payload, null,
                null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"discovery_result_push_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    private async Task ApplyTransportActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = await ApplyTransportAction(argumentsJson);
        await PushActionResultSafelyAsync("session_transport", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    /// <summary>One hub lifecycle act from the host window (Block C
    /// part 2, D28 guided stand-up). Start is gated by the §8 startup
    /// self-check inside HubLifecycle; refusals surface as the action
    /// detail, never as a silent no-op. Decommission DELETES the hub
    /// node (HS-07).</summary>
    public (bool Ok, string Detail) ApplyHubAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "no payload");
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var action = JsonStr(root, "action") ?? "";
            (bool, string) result;
            try
            {
                result = action switch
                {
                    "install" => InstallHub(),
                    "start" => StartHub(),
                    "stop" => StopHub(),
                    "status" => (true, HubStatusDetail()),
                    "decommission" => DecommissionHubNode(JsonStr(root, "deviceId") ?? ""),
                    _ => (false, $"unknown hub action: {action}"),
                };
            }
            catch (HubRefusalException ex)
            {
                result = (false, "hub refused to start: " + ex.Message);
            }
            catch (Exception ex)
            {
                result = (false, $"hub action failed ({ex.GetType().Name}: {ex.Message})");
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"hub_action_via_agent:{action}:{(result.Item1 ? "ok" : "refused")}", "SYSTEM", null));
            return result;
        }
        catch (Exception ex) { return (false, $"malformed hub payload ({ex.GetType().Name})"); }
    }

    private (bool, string) InstallHub()
    {
        Hub.Install();
        return (true, $"hub installed (Headscale v{HubPins.HeadscaleVersion}, pinned commit {HubPins.HeadscaleCommit[..8]}…); config + deny-by-default policy generated");
    }

    private (bool, string) StartHub()
    {
        Hub.Start();
        return (true, "hub running — §8 self-check passed on the on-disk config + policy");
    }

    private (bool, string) StopHub()
    {
        Hub.Stop();
        return (true, "hub stopped");
    }

    private string HubStatusDetail()
    {
        var keys = HubApiKeys.List();
        var usable = keys.Count(k => HubApiKeys.IsUsable(k.Id, DateTimeOffset.UtcNow));
        return $"hub state: {Hub.State}; api keys: {keys.Count} vault-held ({usable} usable); " +
               $"rung selected: {_options.HubRungSelected}; server: {_options.HubServerUrl}";
    }

    private (bool, string) DecommissionHubNode(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return (false, "deviceId required");
        var cmd = HubNodes.Decommission(deviceId, DateTimeOffset.UtcNow);
        return (true, $"hub node deleted for {deviceId} ({cmd})");
    }

    private async Task ApplyHubActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyHubAction(argumentsJson);
        await PushActionResultSafelyAsync("hub", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    // ---- Block F action handlers -----------------------------------
    // Each mirrors the established pattern: parse, act through the
    // service (whose gates are the authority), answer with an
    // action_result, refresh the snapshot. Nothing here re-implements
    // a gate the services already enforce.

    public (bool Ok, string Detail) ApplyEnterpriseAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing enterprise action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed enterprise action: {ex.Message}"); }
        var actor = JsonStr(root, "actorUserId") ?? "device-console"; // BD-WIN-CORE-1 F2: the channel actor is the device console itself, never a payload claim
        switch (action)
        {
            case "policy_status":
                return (true, Enterprise.PolicyState);
            case "policy_reload":
            {
                var (ok, detail) = Enterprise.LoadPolicy();
                // Policy-change teardown (Block H): a reload that
                // DISABLED a feature ends that feature's live
                // effects in the bundle's scope on the spot —
                // calls, surfaces, tunnels, transfer jobs.
                var torn = ApplyPolicyTeardown();
                return (ok, torn > 0
                    ? $"{detail} · teardown: {torn} live feature effect(s) ended by the new policy"
                    : detail);
            }
            case "update_check":
            {
                var version = JsonStr(root, "version") ?? "";
                var d = Enterprise.CheckUpdate(version);
                return (d.Allowed, d.Reason);
            }
            case "audit_verify":
            {
                var v = Enterprise.AuditLog.Verify();
                return (v.Ok, v.Summary);
            }
            case "audit_export":
            {
                var format = JsonStr(root, "format") ?? "json";
                var (ok, detail, path) = Enterprise.ExportAudit(format, actor);
                return (ok, ok ? $"audit exported to {path} — {detail}" : detail);
            }
            case "alerts":
                return (true, Enterprise.Alerts.Alerts.Count == 0
                    ? "no alerts"
                    : string.Join(" · ", Enterprise.Alerts.Alerts.TakeLast(10).Select(a => $"{a.EventClass}: {a.Detail}")));
            case "sync_event":
            {
                if (!root.TryGetProperty("event", out var ev)) return (false, "sync_event needs an event object");
                var evt = new Acp.Shared.Enterprise.DirectoryEvent(
                    JsonStr(ev, "externalScopeBinding") ?? "", JsonStr(ev, "scopeId") ?? "",
                    JsonStr(ev, "userId") ?? "", JsonStr(ev, "displayName") ?? "",
                    JsonStr(ev, "action") ?? "", JsonStr(ev, "externalId") ?? "");
                var r = Enterprise.ApplyDirectoryEvent(evt, actor);
                return (r.Allowed, r.Reason);
            }
            case "break_glass_use":
            {
                var (ok, detail, grant) = Enterprise.UseBreakGlass(JsonStr(root, "scopeId") ?? "",
                    JsonStr(root, "holder1") ?? "", JsonStr(root, "secret1") ?? "",
                    JsonStr(root, "holder2") ?? "", JsonStr(root, "secret2") ?? "",
                    JsonStr(root, "reason") ?? "",
                    root.TryGetProperty("drill", out var dv) && dv.ValueKind == JsonValueKind.True);
                return (ok, ok ? $"BREAK-GLASS GRANTED until {grant!.ExpiresUtc:u} — {detail}" : detail);
            }
            case "break_glass_rotate":
            {
                // The Rotate() surface (Block H; authority shape
                // per D38 fix F2): ONE holder per act, and the
                // actor IS that holder — the payload's free-text
                // actorUserId is NOT honored here; the holder id
                // in the act is the actor, and the service demands
                // the holder's current secret as proof plus a
                // pending rotation. A second holder named in the
                // payload is refused by the service, never applied.
                var rotations = new List<(string, string, string)>();
                if (!string.IsNullOrWhiteSpace(JsonStr(root, "holder1")))
                    rotations.Add((JsonStr(root, "holder1")!,
                        JsonStr(root, "currentSecret1") ?? "", JsonStr(root, "newSecret1") ?? ""));
                if (!string.IsNullOrWhiteSpace(JsonStr(root, "holder2")))
                    rotations.Add((JsonStr(root, "holder2")!,
                        JsonStr(root, "currentSecret2") ?? "", JsonStr(root, "newSecret2") ?? ""));
                var rotateActor = rotations.Count > 0 ? rotations[0].Item1 : actor;
                var (ok, detail) = Enterprise.RotateBreakGlassHolders(rotateActor, rotations);
                return (ok, detail);
            }
            case "idp_begin":
            {
                var (ok, detail) = Enterprise.BeginMockIdpSignIn(
                    JsonStr(root, "subject") ?? "", JsonStr(root, "email") ?? "",
                    root.TryGetProperty("emailVerified", out var evv) && evv.ValueKind == JsonValueKind.True);
                return (ok, detail);
            }
            case "idp_complete":
            {
                var (ok, detail, subject) = Enterprise.CompleteMockIdpSignIn();
                return (ok, ok ? $"mock IdP sign-in complete for {subject} — {detail}" : detail);
            }
            case "idp_begin_real":
            {
                // W11 / R-21: the real OIDC leg. Issuer + client id
                // come from the operator's action payload (no IdP
                // is configured by default); the answer carries the
                // authorization URL for the user's own browser.
                var issuer = JsonStr(root, "issuer");
                var clientId = JsonStr(root, "clientId");
                if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(clientId))
                    return (false, "idp_begin_real needs an issuer and a clientId — refused");
                var (ok, detail, url) = Enterprise.BeginRealIdpSignIn(new Shared.Enterprise.OidcConfig(
                    issuer, clientId, JsonStr(root, "redirectUri") ?? "acp://oidc/callback",
                    RequirePkceS256: true, RequireEmailVerified: true));
                return (ok, ok ? $"{detail} | authorizationUrl={url}" : detail);
            }
            case "idp_complete_real":
            {
                var (ok, detail, subject) = Enterprise.CompleteRealIdpSignIn(JsonStr(root, "code") ?? "");
                return (ok, ok ? $"real IdP sign-in complete for {subject} — {detail}" : detail);
            }
            default:
                return (false, $"unknown enterprise action '{action}'");
        }
    }

    /// <summary>Block G service acts from the host window's
    /// Services page (Block H exposure): wake registry + send,
    /// standalone transfers (list + the device-side cancel),
    /// session tunnels (list + close), factor counts. Every rule
    /// is the service's own — this dispatch only carries the act
    /// and reports the service's answer verbatim. The actor for
    /// gated acts comes from the payload's actorUserId (the panel
    /// asks for it, exactly like the directory-sync form).</summary>
    public (bool Ok, string Detail) ApplyBlockGAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing blockg action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed blockg action: {ex.Message}"); }
        var actor = JsonStr(root, "actorUserId") ?? "";
        switch (action)
        {
            case "wake_list":
            {
                var targets = Wake.ListTargets();
                return (true, targets.Count == 0
                    ? "no wake targets registered on this host"
                    : string.Join("\n", targets.Select(t => $"{t.DeviceId} · {t.MacAddress} · via {t.BroadcastAddress}")));
            }
            case "wake_register":
            {
                var ok = Wake.RegisterTarget(JsonStr(root, "deviceId") ?? "",
                    JsonStr(root, "mac") ?? "", JsonStr(root, "broadcast") ?? "",
                    string.IsNullOrWhiteSpace(actor) ? null : actor);
                return (ok, ok ? "wake target registered" : "registration refused (device, MAC, or admin check failed)");
            }
            case "wake_unregister":
            {
                var ok = Wake.UnregisterTarget(JsonStr(root, "deviceId") ?? "",
                    string.IsNullOrWhiteSpace(actor) ? null : actor);
                return (ok, ok ? "wake target removed" : "removal refused (unknown target or admin check failed)");
            }
            case "wake_send":
            {
                var (sent, detail) = Wake.SendWake(JsonStr(root, "deviceId") ?? "", actor);
                return (sent, detail);
            }
            case "transfers_list":
            {
                var scopeId = JsonStr(root, "scopeId") ?? "";
                var jobs = StandaloneTransfers.ListJobs(scopeId);
                return (true, jobs.Count == 0
                    ? $"no standalone transfer jobs in scope '{scopeId}'"
                    : string.Join("\n", jobs.Select(j =>
                        $"{j.Id} · '{j.Name}' · {j.Direction} · {j.State} · {j.TransferredBytes}/{j.SizeBytes} bytes · device {j.DeviceId} · initiator {j.InitiatorUserId}")));
            }
            case "transfer_cancel":
            {
                var jobId = JsonStr(root, "jobId") ?? "";
                var ok = StandaloneTransfers.CancelJob(jobId, actor);
                return (ok, ok
                    ? $"transfer job {jobId} cancelled from the device side"
                    : "cancel refused (job unknown/terminal, or the actor is neither its initiator nor a company admin of its scope)");
            }
            case "transfer_cancel_device":
            {
                // Device-presence stop (D38 fix F10): the person
                // at THIS machine stops any live job; no actor is
                // taken from the payload — a typed roster id here
                // would be an unverifiable claim, and the audit
                // records the reserved device-console actor.
                var jobId = JsonStr(root, "jobId") ?? "";
                var ok = StandaloneTransfers.CancelJobFromDevice(jobId);
                return (ok, ok
                    ? $"transfer job {jobId} stopped from the device console"
                    : "stop refused (job unknown or already terminal)");
            }
            case "tunnels_list":
            {
                var scopeId = JsonStr(root, "scopeId") ?? "";
                var open = SessionTunnels.ListOpen().Where(t =>
                {
                    var s = HumanSessions.GetSession(t.SessionId);
                    return s is not null && string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase);
                }).ToList();
                return (true, open.Count == 0
                    ? $"no open session tunnels in scope '{scopeId}'"
                    : string.Join("\n", open.Select(t =>
                        $"{t.Id} · session {t.SessionId} · :{t.ListenPort} → {t.TargetHost}:{t.TargetPort} · opened by {t.OpenedByUserId}")));
            }
            case "tunnel_close":
            {
                var tunnelId = JsonStr(root, "tunnelId") ?? "";
                var ok = SessionTunnels.Close(tunnelId, actor);
                return (ok, ok
                    ? $"tunnel {tunnelId} closed from the device side"
                    : "close refused (tunnel unknown/closed, or the actor may not close it)");
            }
            case "tunnel_close_device":
            {
                // Device-presence close (D38 fix F10): no actor
                // from the payload — the panel's tunnel card used
                // to send the WAKE card's actor box, attributing
                // the close to whoever was typed there.
                var tunnelId = JsonStr(root, "tunnelId") ?? "";
                var ok = SessionTunnels.CloseFromDevice(tunnelId);
                return (ok, ok
                    ? $"tunnel {tunnelId} closed from the device console"
                    : "close refused (tunnel unknown or already closed)");
            }
            case "factor_status":
            {
                var (totp, passkeys) = SecondFactors.Counts();
                return (true, $"active TOTP enrollments: {totp} · registered passkeys: {passkeys} (counts only — factor material never surfaces)");
            }
            default:
                return (false, $"unknown blockg action '{action}'");
        }
    }

    public (bool Ok, string Detail) ApplyTerminalAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing terminal action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed terminal action: {ex.Message}"); }
        var actor = JsonStr(root, "actorUserId") ?? "";
        switch (action)
        {
            case "open":
            {
                var (ok, detail, t) = Terminals.Open(JsonStr(root, "sessionId") ?? "", actor, DateTimeOffset.UtcNow);
                return (ok, ok ? $"terminal {t!.Id} open on session {t.SessionId}" : detail);
            }
            case "write":
            {
                var (ok, detail) = Terminals.Write(JsonStr(root, "terminalId") ?? "", actor, JsonStr(root, "text") ?? "");
                return (ok, detail);
            }
            case "close":
            {
                var (ok, detail) = Terminals.Close(JsonStr(root, "terminalId") ?? "", actor);
                return (ok, detail);
            }
            case "output":
            {
                var lines = Terminals.Output(JsonStr(root, "terminalId") ?? "");
                return (true, lines.Count == 0 ? "(no output yet)" : string.Join("\n", lines.TakeLast(60)));
            }
            case "status":
            {
                var open = Terminals.OpenTerminalFor(JsonStr(root, "sessionId") ?? "");
                return (true, open is null ? "no terminal open on this session" : $"terminal {open.Id} open (opened by {open.OpenedByUserId})");
            }
            case "write_session":
            {
                var open = Terminals.OpenTerminalFor(JsonStr(root, "sessionId") ?? "");
                if (open is null) return (false, "no terminal open on this session");
                var (ok, detail) = Terminals.Write(open.Id, actor, JsonStr(root, "text") ?? "");
                return (ok, detail);
            }
            case "close_session":
            {
                var open = Terminals.OpenTerminalFor(JsonStr(root, "sessionId") ?? "");
                if (open is null) return (false, "no terminal open on this session");
                var (ok, detail) = Terminals.Close(open.Id, actor);
                return (ok, detail);
            }
            case "output_session":
            {
                var open = Terminals.OpenTerminalFor(JsonStr(root, "sessionId") ?? "");
                if (open is null) return (false, "no terminal open on this session");
                var lines = Terminals.Output(open.Id);
                return (true, lines.Count == 0 ? "(no output yet)" : string.Join("\n", lines.TakeLast(60)));
            }
            default:
                return (false, $"unknown terminal action '{action}'");
        }
    }

    public (bool Ok, string Detail) ApplyQuickAssistAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing quick assist action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed quick assist action: {ex.Message}"); }
        switch (action)
        {
            case "mint":
            {
                var display = QuickAssist.Mint(
                    JsonStr(root, "scopeId") ?? "", JsonStr(root, "hostDeviceId") ?? "",
                    JsonStr(root, "initiatorUserId") ?? "", DateTimeOffset.UtcNow);
                _ = PushQuickAssistCodeSafelyAsync(display);
                return (true, "quick-assist code minted — shown once in the window; view-only, single-use, 10 minutes");
            }
            case "redeem":
            {
                var (ok, detail, grant, _) = QuickAssist.Redeem(JsonStr(root, "code"), JsonStr(root, "clientBinding") ?? "", DateTimeOffset.UtcNow);
                return (ok, ok ? $"view-only grant {grant!.GrantId} issued (expires {grant.ExpiresUtc:u})" : detail);
            }
            case "close":
            {
                var id = JsonStr(root, "id");
                var closed = !string.IsNullOrEmpty(id)
                    ? QuickAssist.Close(id)
                    : QuickAssist.CloseCode(JsonStr(root, "code"));
                return (closed, "quick-assist code/grant closed (the code is dead)");
            }
            case "validate":
            {
                var (ok, detail, _) = QuickAssist.Validate(JsonStr(root, "grantId"), JsonStr(root, "token"),
                    JsonStr(root, "clientBinding") ?? "", DateTimeOffset.UtcNow);
                return (ok, detail);
            }
            default:
                return (false, $"unknown quick assist action '{action}'");
        }
    }

    private async Task PushQuickAssistCodeSafelyAsync(string displayCode)
    {
        try
        {
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.QuickAssistCode, null, null,
                JsonSerializer.Serialize(new { code = displayCode, expiresUtc = DateTimeOffset.UtcNow.AddMinutes(10) }),
                null, null, null, null, null, null), _cts.Token);
        }
        catch { /* the action_result already told the operator the mint succeeded */ }
    }

    public (bool Ok, string Detail) ApplyWebRtcAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing webrtc action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed webrtc action: {ex.Message}"); }
        switch (action)
        {
            case "create_code":
            {
                var code = WebRtc.CreateCode(JsonStr(root, "kind") ?? "offer",
                    JsonStr(root, "sessionId") ?? "", JsonStr(root, "sdp") ?? "", Identity, DateTimeOffset.UtcNow);
                return (true, code);
            }
            case "accept_code":
            {
                var (ok, detail, _) = WebRtc.AcceptCode(JsonStr(root, "code") ?? "", JsonStr(root, "sdp") ?? "", DateTimeOffset.UtcNow);
                return (ok, detail);
            }
            case "media_status":
                return (true, Acp.Shared.WebRtc.WebRtcMediaStatus.Explanation);
            default:
                return (false, $"unknown webrtc action '{action}'");
        }
    }

    // ---- W19-C wiring: Tor provisioning + AiPack download -----------
    // Both acts were built but unreachable in v18 (W18 deploy
    // findings): TorSetupService.RunSetupAsync had no production
    // caller, and the AiPack IPC surface had no download action.
    // They are wired here exactly the way their neighbours are:
    // laptop-UI-only IPC kinds, policy toggles consulted per act,
    // file-audit entry per act (the Safely wrappers), chained-audit
    // entries for the consequential outcomes, and honest states.

    private bool ManagementPolicyAllows(string key) =>
        ManagementPolicies.IsEnabled(
            Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, ""), key);

    // -- Tor state: the last setup act's outcome in THIS Core. The
    // status act combines it with live facts (process running,
    // tor.json present, binary present) so a restarted Core reports
    // the disk truth, not a stale memory.
    // W22 (round-4): _torActState/_torActDetail are guarded
    // by _torActLock, and the setup claim goes through
    // TryClaimTorSetup — the pre-fix check/set was two unguarded
    // statements, so two concurrent IPC dispatches could both pass
    // the "configuring" check and both run setup.
    private readonly object _torActLock = new();
    private string _torActState = "unconfigured";
    private string _torActDetail = "";

    /// <summary>W22: atomically claim the Tor setup act. Exactly
    /// one caller wins while a setup is in flight; every concurrent
    /// caller is refused. Internal so the harness can hammer it
    /// concurrently and pin the exactly-one-winner property.</summary>
    internal bool TryClaimTorSetup()
    {
        lock (_torActLock)
        {
            if (_torActState == "configuring") return false;
            _torActState = "configuring"; _torActDetail = "";
            return true;
        }
    }

    private void SetTorActState(string state, string detail)
    {
        lock (_torActLock) { _torActState = state; _torActDetail = detail; }
    }

    private (string State, string Detail) TorActSnapshot()
    {
        lock (_torActLock) return (_torActState, _torActDetail);
    }

    /// <summary>The Tor provisioning surface (IpcKinds.TorAction):
    /// setup | status | stop. Setup is the setup act's first
    /// production caller.</summary>
    public async Task<(bool Ok, string Detail)> ApplyTorActionAsync(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing tor action payload");
        string action;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            action = JsonStr(doc.RootElement, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed tor action: {ex.Message}"); }
        switch (action)
        {
            case "status":
                return (true, TorStatusDetail());
            case "setup":
            {
                if (!ManagementPolicyAllows(TorProvisioningPolicyKey))
                    return (false, $"tor setup refused: feature '{TorProvisioningPolicyKey}' is disabled by management policy for this device (TOTAL POLICY CONTROL)");
                // W22: the claim is atomic (TryClaimTorSetup) —
                // concurrent setup is truly refused, not racily.
                if (!TryClaimTorSetup())
                    return (false, "tor setup refused: a setup act is already in progress");
                try
                {
                    var (ok, detail) = await TorSetup.RunSetupAsync();
                    SetTorActState(ok ? "ready" : "failed", detail);
                    try { Enterprise.AppendServiceAudit("tor_setup", "device-console",
                        ok ? $"tor setup completed: {detail}" : $"tor setup FAILED: {detail}"); } catch { }
                    return (ok, detail);
                }
                catch (Exception ex)
                {
                    var failedDetail = $"tor setup failed ({ex.GetType().Name}) — the rung stays unconfigured";
                    SetTorActState("failed", failedDetail);
                    try { Enterprise.AppendServiceAudit("tor_setup", "device-console", $"tor setup FAILED: {failedDetail}"); } catch { }
                    return (false, failedDetail);
                }
            }
            case "stop":
            {
                // A stop is never policy-gated (the Block G
                // device-console stop precedent): the person at the
                // machine can always turn Tor off.
                TorSetup.StopAndUnconfigure();
                SetTorActState("unconfigured", "");
                try { Enterprise.AppendServiceAudit("tor_stop", "device-console", "tor stopped by the device console; tor.json removed — the rung is unconfigured"); } catch { }
                return (true, "tor stopped: ACP-managed client stopped and tor.json removed — the tor rung is honestly unconfigured again");
            }
            default:
                return (false, $"unknown tor action '{action}'");
        }
    }

    private string TorStatusDetail()
    {
        var configured = File.Exists(TorSetup.TorConfigPath);
        var artefact = TorSetup.Manifest.ForCurrentPlatform();
        var binaryInstalled = artefact is not null && File.Exists(Path.Combine(
            TorSetup.ComponentHome, artefact.BinaryBundlePath.Replace('/', Path.DirectorySeparatorChar)));
        var (actState, actDetail) = TorActSnapshot();
        string state, detail;
        if (actState == "configuring")
        { state = "configuring"; detail = "a Tor setup act is in progress (provisioning/verifying/launching)"; }
        else if (TorSetup.IsRunning && configured)
        { state = "ready"; detail = $"ACP-managed Tor client running — local SOCKS proxy at {Shared.Tor.TorPins.SocksHost}:{Shared.Tor.TorPins.SocksPort}, binary verified against its pin before launch; tor.json written by Tor setup"; }
        else if (actState == "failed")
        { state = "failed"; detail = actDetail; }
        else if (configured)
        { state = "configured"; detail = "tor.json is present (written by a previous setup act) but the ACP-managed client is not running in this Core — run setup to launch it"; }
        else if (binaryInstalled)
        { state = "unconfigured"; detail = "the pinned Tor component is installed but tor.json is absent — run setup to verify, launch, and configure the rung"; }
        else
        { state = "unconfigured"; detail = "no tor.json and the pinned Tor component is not provisioned — run setup to provision it"; }
        // DESIGN ITEM (named, not faked): the product's Tor
        // component is client-only — no onion service exists. A
        // session leg to a private/LAN target is refused by Tor's
        // exits (proven live in W18); reaching this endpoint OVER
        // Tor needs an onion-service design the trio has not taken.
        return $"tor state: {state} — {detail} · component: Tor {TorSetup.Manifest.TorVersion} (expert bundle {TorSetup.Manifest.BundleVersion}), audit status {TorSetup.Manifest.AuditStatus} · onion service: none (client-only component — DESIGN ITEM, not implemented; private-target refusal is Tor's own behaviour)";
    }

    private async Task ApplyTorActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = await ApplyTorActionAsync(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"tor_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("tor", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    // -- AiPack download state: one download at a time, owned by
    // the Core; the act that started it answers immediately and the
    // completion lands as its own action_result + chained audit.
    private readonly object _aipackDownloadLock = new();
    private string _aipackDownloadState = "not_started"; // not_started|downloading|ready|failed|cancelled
    private string _aipackDownloadDetail = "";
    private int _aipackFilesLanded;
    private string? _aipackCurrentFile;
    private CancellationTokenSource? _aipackDownloadCts;

    public (string State, string Detail, int FilesLanded, int FilesTotal, string? CurrentFile) AiPackDownloadSnapshot()
    {
        lock (_aipackDownloadLock)
            return (_aipackDownloadState, _aipackDownloadDetail, _aipackFilesLanded,
                AiPack.Manifest.Files.Count, _aipackCurrentFile);
    }

    private string AiPackDownloadStatusDetail()
    {
        var (state, detail, landed, total, current) = AiPackDownloadSnapshot();
        var head = state switch
        {
            "not_started" => "aipack download state: not_started — no download has been started in this Core",
            "downloading" => $"aipack download state: downloading — {landed}/{total} file(s) landed and verified" +
                             (current is null ? "" : $"; current file: {current}"),
            "ready" => $"aipack download state: ready — {total}/{total} file(s) in the pack home, every hash verified against the pinned hashes",
            "failed" => $"aipack download state: failed — {detail}",
            "cancelled" => $"aipack download state: cancelled — {detail}",
            _ => $"aipack download state: {state}",
        };
        return $"{head} · pack home: {AiPackHome} · resumable: files already landed that still verify against their pins are skipped on a restart of the download; the in-flight file restarts";
    }

    private (bool Ok, string Detail) StartAiPackDownload()
    {
        if (!ManagementPolicyAllows(AiPackDownloadPolicyKey))
            return (false, $"aipack download refused: feature '{AiPackDownloadPolicyKey}' is disabled by management policy for this device (TOTAL POLICY CONTROL)");
        if (!AiPack.LicenceAccepted)
            return (false, "aipack download refused: licence not accepted — the wizard shows the licence before any download (D25); use the licence + accept_licence actions first");
        lock (_aipackDownloadLock)
        {
            if (_aipackDownloadState == "downloading")
                return (false, "aipack download refused: a download is already in progress — download_status reports it, download_cancel stops it");
            _aipackDownloadState = "downloading";
            _aipackDownloadDetail = "";
            _aipackFilesLanded = 0;
            _aipackCurrentFile = null;
            _aipackDownloadCts = new CancellationTokenSource();
        }
        var cts = _aipackDownloadCts!;
        try { Enterprise.AppendServiceAudit("aipack_download_started", "device-console",
            $"pack download started into the pack home {AiPackHome} ({AiPack.Manifest.Files.Count} pinned file(s), official source only)"); } catch { }
        _ = Task.Run(() => RunAiPackDownloadAsync(cts, ct => AiPack.DownloadAsync(AiPackHome, AiPackService.HttpFetchResumableAsync,
            ct: ct,
            onFileLanded: (landedCount, _, file) =>
            {
                lock (_aipackDownloadLock) { _aipackFilesLanded = landedCount; _aipackCurrentFile = file; }
            })));
        return (true, $"aipack download started: {AiPack.Manifest.Files.Count} pinned file(s) from the author's official source into the pack home {AiPackHome} — every file is hash-verified before it lands and any mismatch refuses with no override; download_status reports progress, download_cancel stops it (landed verified files are kept and skipped on restart)");
    }

    /// <summary>W22 (round-4): the AiPack download body,
    /// with the failure path the pre-fix Task.Run lacked — it had
    /// no try/catch, so ANY throw out of DownloadAsync (a cancelled
    /// hash read, an IO fault in a progress callback, a fetcher
    /// seam surprise) wedged the state at "downloading" with no
    /// failure audit until a Core restart, and download refused
    /// every retry as "already in progress". Now whatever throws
    /// lands here: state → failed (or cancelled, when the download
    /// token fired) WITH the reason, a chained
    /// aipack_download_failed/cancelled service-audit entry, and
    /// the action_result push — the same completion surface as a
    /// clean return. Internal so the harness can drive the throw
    /// path deterministically with a throwing download delegate.</summary>
    internal async Task RunAiPackDownloadAsync(CancellationTokenSource cts,
        Func<CancellationToken, Task<(bool Ok, string Detail)>> download)
    {
        bool ok; string detail; bool cancelled;
        try
        {
            (ok, detail) = await download(cts.Token);
            cancelled = cts.IsCancellationRequested;
        }
        catch (Exception ex)
        {
            cancelled = cts.IsCancellationRequested;
            ok = false;
            detail = cancelled
                ? $"download cancelled ({ex.GetType().Name}) — the in-flight file's partial is discarded; landed verified files are kept"
                : $"download failed ({ex.GetType().Name}: {ex.Message}) — the download body threw; no file was accepted on the strength of a partial transfer, and the state is failed-with-reason, not wedged at downloading";
        }
        lock (_aipackDownloadLock)
        {
            _aipackDownloadState = ok ? "ready" : cancelled ? "cancelled" : "failed";
            _aipackDownloadDetail = detail;
            _aipackCurrentFile = null;
        }
        try { Enterprise.AppendServiceAudit(
            ok ? "aipack_download_completed" : cancelled ? "aipack_download_cancelled" : "aipack_download_failed",
            "device-console", detail); } catch { }
        await PushActionResultSafelyAsync("aipack_download", ok,
            cancelled && !ok ? $"download cancelled — {detail}" : detail);
        _ = PushHostStateSafelyAsync();
    }

    /// <summary>W22: the host-resolved identity of the
    /// authenticated device-console channel — the OS console
    /// session's user SID, resolved by the host (the
    /// IpcTokenFileChannel resolver), formatted as
    /// "console-user:&lt;sid&gt;". Off-Windows or unresolvable it
    /// falls back to the channel's standing name "device-console".
    /// This — never a payload field — is who channel acts are
    /// attributed to (the W7/W9 pattern: host-resolved identity
    /// wins, body-supplied identity is ignored).</summary>
    internal string ChannelConsoleIdentity()
    {
        try
        {
            var sid = Services.IpcTokenFileChannel.ResolveConsoleUserSid();
            if (!string.IsNullOrWhiteSpace(sid)) return $"console-user:{sid}";
        }
        catch { }
        return "device-console";
    }

    private (bool Ok, string Detail) CancelAiPackDownload()
    {
        // A cancel is never policy-gated (device-console stop precedent).
        lock (_aipackDownloadLock)
        {
            if (_aipackDownloadState != "downloading" || _aipackDownloadCts is null)
                return (false, "aipack download_cancel refused: no download is in progress");
            _aipackDownloadCts.Cancel();
        }
        return (true, "aipack download cancelling — the in-flight file's partial is discarded; files already landed and verified stay in the pack home and are skipped if the download is restarted");
    }

    public (bool Ok, string Detail) ApplyAiPackAction(string? argumentsJson)
    {
        if (argumentsJson is null) return (false, "missing aipack action payload");
        string action;
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            root = doc.RootElement.Clone();
            action = JsonStr(root, "action") ?? "";
        }
        catch (Exception ex) { return (false, $"malformed aipack action: {ex.Message}"); }
        switch (action)
        {
            case "status":
            {
                var m = AiPack.Manifest;
                return (true, $"{m.DisplayName} ({m.LicenseId}) from {m.OfficialBaseUrl} — pins captured: {m.PinsCaptured}; " +
                    $"files: {m.Files.Count}; runtime audit status: {m.AuditStatus} (T7/S11 — unaudited, recorded honestly); " +
                    $"pack AI identity: {AiPackManifest.PackUserId} (a leashed AI participant, never admin); " +
                    $"pack home: {AiPackHome}; {AiPackDownloadStatusDetail()}");
            }
            case "licence":
                return (true, AiPack.LicenceToShow());
            case "accept_licence":
            {
                // W22 (round-4): the pre-fix shape recorded
                // the acceptance under a PAYLOAD-supplied userId —
                // forgeable attribution for the one act the download
                // gate checks. The acceptance is now bound to the
                // AUTHENTICATED identity on this channel: the action
                // arrives only over the token-authenticated,
                // OS-identity-verified agent IPC channel from the
                // laptop UI, and the identity recorded is the
                // host-resolved console identity
                // (ChannelConsoleIdentity). A body "userId" is
                // IGNORED entirely — read nowhere, recorded nowhere
                // (the W7/W9 host-resolved-identity pattern).
                var acceptedBy = ChannelConsoleIdentity();
                AiPack.AcceptLicence(acceptedBy);
                try { Enterprise.AppendServiceAudit("aipack_licence_accepted", acceptedBy,
                    "AiPack licence accepted via the authenticated device-console channel; acceptance bound to the host-resolved channel identity (any payload userId ignored)"); } catch { }
                return (true, $"licence accepted for {acceptedBy}; a download still verifies every file hash and refuses on any mismatch — no override exists");
            }
            case "verify":
            {
                // No directory named = the product's pack home
                // (W19-C: the window's verify button carries none);
                // an explicitly named directory is still honoured,
                // as before — verify is a read-only check.
                var dir = JsonStr(root, "directory");
                if (string.IsNullOrWhiteSpace(dir)) dir = AiPackHome;
                var (ok, detail) = AiPack.VerifyInstalledAsync(dir).GetAwaiter().GetResult();
                return (ok, detail);
            }
            // W19-C: the download act — before this case the pack
            // could never be fetched by the product (W18 finding).
            // It lands ONLY in the product's pack home: a payload
            // directory is refused by name, never honoured (the
            // laptop's D: staging was a deploy workaround, not a
            // product surface).
            case "download":
            {
                if (JsonStr(root, "directory") is { Length: > 0 } dir &&
                    !string.Equals(dir, AiPackHome, StringComparison.OrdinalIgnoreCase))
                    return (false, $"aipack download refused: downloads land only in the product's pack home ({AiPackHome}) — '{dir}' is not a download target (verify may still be pointed at another directory)");
                return StartAiPackDownload();
            }
            case "download_status":
                return (true, AiPackDownloadStatusDetail());
            case "download_cancel":
                return CancelAiPackDownload();
            default:
                return (false, $"unknown aipack action '{action}'");
        }
    }

    private async Task ApplyEnterpriseActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyEnterpriseAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"enterprise_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("enterprise", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    private async Task ApplyTerminalActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyTerminalAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"terminal_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("terminal", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    private async Task ApplyQuickAssistActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyQuickAssistAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"quick_assist_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("quick_assist", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    private async Task ApplyWebRtcActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyWebRtcAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"webrtc_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("webrtc", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    private async Task ApplyAiPackActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyAiPackAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"aipack_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("aipack", ok, detail);
    }

    private async Task ApplyBlockGActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyBlockGAction(argumentsJson);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            $"blockg_action_via_agent:{(ok ? "ok" : "refused")}", "SYSTEM", null));
        await PushActionResultSafelyAsync("blockg", ok, detail);
    }

    /// <summary>The ownpath rung's peer set (Block F): ACP-generated
    /// WireGuard peers live in ownpath-peers.json in the data dir
    /// (written by the enrollment/own-path tooling with the T5
    /// serializer; read fresh at connect time so a swapped file is
    /// re-validated by the rung before any session rides it).</summary>
    private static OwnPathPeerSet ReadOwnPathPeers(string dataDir)
    {
        try
        {
            var path = Path.Combine(dataDir, "ownpath-peers.json");
            if (!File.Exists(path)) return OwnPathPeerSet.Empty;
            var peers = JsonSerializer.Deserialize<List<OwnPathPeer>>(File.ReadAllText(path));
            return peers is null ? OwnPathPeerSet.Empty
                : new OwnPathPeerSet(peers.ToDictionary(p => p.DeviceId, p => p, StringComparer.OrdinalIgnoreCase));
        }
        catch { return OwnPathPeerSet.Empty; }
    }

    /// <summary>ACP's Tor configuration (Block F): tor.json in the
    /// data dir — {"socksHost": "127.0.0.1", "socksPort": 9050} for
    /// the ACP-managed Tor client. Absent/malformed = the rung is
    /// unconfigured and refuses honestly.</summary>
    private static TorConfig? ReadTorConfig(string dataDir)
    {
        try
        {
            var path = Path.Combine(dataDir, "tor.json");
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var host = doc.RootElement.TryGetProperty("socksHost", out var h) ? h.GetString() : null;
            var port = doc.RootElement.TryGetProperty("socksPort", out var p) ? p.GetInt32() : 0;
            return host is null || port <= 0 ? null : new TorConfig(host, port);
        }
        catch { return null; }
    }

    /// <summary>Mint a hub join ticket from the host window (D28): ACP
    /// mints the single-use pre-auth key under the hood; the ticket is
    /// returned for one-time display to the operator at the keyboard,
    /// exactly like an enrollment code. The joining endpoint applies
    /// the command itself and never sees an account or a sign-in (D3).</summary>
    private async Task PushHubJoinTicketSafelyAsync(string? argumentsJson)
    {
        try
        {
            string deviceId = "", groupId = "";
            if (argumentsJson is not null)
            {
                using var doc = JsonDocument.Parse(argumentsJson);
                deviceId = JsonStr(doc.RootElement, "deviceId") ?? "";
                groupId = JsonStr(doc.RootElement, "groupId") ?? "";
            }
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                await PushActionResultSafelyAsync("hub_mint_join", false, "deviceId required");
                return;
            }
            var ticket = HubJoins.MintJoinTicket(deviceId, groupId, _options.HubServerUrl, DateTimeOffset.UtcNow);
            var payload = JsonSerializer.Serialize(new
            {
                deviceId = ticket.DeviceId,
                command = ticket.CommandLine,
                expiresUtc = ticket.ExpiresUtc,
            });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.HubJoinTicket, null, null, payload, null,
                null, null, null, null, null), _cts.Token);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"hub_join_ticket_minted:{deviceId}", "SYSTEM", null));
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"hub_join_ticket_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    private async Task ApplyRosterActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyRosterAction(argumentsJson);
        await PushActionResultSafelyAsync("roster", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    // ---- C20 recovery acts (owner-local, companion window only) -----
    // Reached ONLY from the authenticated agent-IPC channel above —
    // the same trust basis as gate approvals and the vault. Every
    // refusal is LOUD: the C20 service's reason goes back to the
    // window in the action result (the owner typed the credential;
    // the reason may quote their own mistyped word). The reason is
    // NEVER copied into the audit log (OwnerRecoveryService audits
    // fixed outcome strings only) and the key sheet NEVER appears in
    // the action result — it transits only the RecoveryKeySheet
    // message below, once, to the window.

    public (bool Ok, string Detail, RecoveryExportResult? Exported, string? PrimaryPath, IReadOnlyList<string> ContactPaths)
        ApplyRecoveryAction(string? argumentsJson)
    {
        IReadOnlyList<string> noPaths = Array.Empty<string>();
        if (argumentsJson is null) return (false, "no payload", null, null, noPaths);
        try
        {
            using var doc = JsonDocument.Parse(argumentsJson);
            var root = doc.RootElement;
            var action = JsonStr(root, "action") ?? "";
            switch (action)
            {
                case "export":
                {
                    var outputPath = JsonStr(root, "outputPath");
                    if (string.IsNullOrWhiteSpace(outputPath))
                        return (false, "export refused: no output path — pick where the recovery blob goes in the save dialog first", null, null, noPaths);
                    var contacts = new List<RecoveryContact>();
                    if (root.TryGetProperty("contacts", out var cs) && cs.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var c in cs.EnumerateArray())
                        {
                            var name = JsonStr(c, "name") ?? "";
                            var keyB64 = JsonStr(c, "publicKeyBase64") ?? "";
                            byte[] key;
                            try { key = Convert.FromBase64String(keyB64); }
                            catch { return (false, $"export refused: recovery contact '{name}' public key is not base64", null, null, noPaths); }
                            contacts.Add(new RecoveryContact(name, key));
                        }
                    }
                    var exported = Recovery.Export(JsonStr(root, "passphrase") ?? "", contacts);
                    var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    File.WriteAllBytes(outputPath, exported.PrimaryBlob);
                    var contactPaths = new List<string>();
                    foreach (var (contact, blob) in exported.ContactBlobs)
                    {
                        var safe = string.Concat(contact.Name.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_'));
                        var p = outputPath + $".contact-{safe}.acprecovery";
                        File.WriteAllBytes(p, blob);
                        contactPaths.Add(p);
                    }
                    return (true,
                        $"recovery blob exported for device {exported.DeviceId} to {outputPath}" +
                        (contactPaths.Count > 0 ? $" plus {contactPaths.Count} sealed contact cop{(contactPaths.Count == 1 ? "y" : "ies")}" : "") +
                        " — the key sheet is shown once in this window; it is not stored anywhere",
                        exported, outputPath, contactPaths);
                }
                case "inspect":
                {
                    var blobPath = JsonStr(root, "blobPath");
                    if (string.IsNullOrWhiteSpace(blobPath) || !File.Exists(blobPath))
                        return (false, "inspect refused: no such blob file — pick the recovery blob first", null, null, noPaths);
                    var info = Recovery.Inspect(File.ReadAllBytes(blobPath));
                    return (true,
                        $"recovery blob: kind {info.Kind}, device {info.DeviceId}, created {info.CreatedUtc:u}" +
                        (info.ContactName is null ? "" : $", sealed to contact '{info.ContactName}'"),
                        null, null, noPaths);
                }
                case "restore_primary":
                {
                    var blobPath = JsonStr(root, "blobPath");
                    if (string.IsNullOrWhiteSpace(blobPath) || !File.Exists(blobPath))
                        return (false, "restore refused: no such blob file — pick the recovery blob first", null, null, noPaths);
                    var result = Recovery.RestorePrimary(
                        File.ReadAllBytes(blobPath), JsonStr(root, "passphrase"), JsonStr(root, "keySheet"));
                    return (true,
                        $"recovery restored: device {result.DeviceId}, {result.PairingsRestored} pairing(s), " +
                        $"{result.RosterEntriesRestored} roster entr{(result.RosterEntriesRestored == 1 ? "y" : "ies")} — " +
                        "restart the Core service so every service rebinds to the restored identity",
                        null, null, noPaths);
                }
                case "restore_contact":
                {
                    var blobPath = JsonStr(root, "blobPath");
                    if (string.IsNullOrWhiteSpace(blobPath) || !File.Exists(blobPath))
                        return (false, "restore refused: no such blob file — pick the sealed contact copy first", null, null, noPaths);
                    var seedB64 = JsonStr(root, "contactSeedBase64");
                    if (string.IsNullOrWhiteSpace(seedB64))
                        return (false, "restore refused: a contact-copy restore needs the named contact's identity seed, presented at this machine", null, null, noPaths);
                    byte[] seed;
                    try { seed = Convert.FromBase64String(seedB64); }
                    catch { return (false, "restore refused: the contact seed is not base64", null, null, noPaths); }
                    try
                    {
                        var result = Recovery.RestoreFromContactCopy(
                            File.ReadAllBytes(blobPath), seed, JsonStr(root, "keySheet") ?? "");
                        return (true,
                            $"recovery restored from contact copy: device {result.DeviceId}, {result.PairingsRestored} pairing(s), " +
                            $"{result.RosterEntriesRestored} roster entr{(result.RosterEntriesRestored == 1 ? "y" : "ies")} — " +
                            "restart the Core service so every service rebinds to the restored identity",
                            null, null, noPaths);
                    }
                    finally { CryptographicOperations.ZeroMemory(seed); }
                }
                default:
                    return (false, $"unknown recovery action: {action}", null, null, noPaths);
            }
        }
        catch (RecoveryBlobException ex) { return (false, ex.Message, null, null, noPaths); }
        catch (Exception ex) { return (false, $"recovery action failed ({ex.GetType().Name}: {ex.Message})", null, null, noPaths); }
    }

    private async Task ApplyRecoveryActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail, exported, primaryPath, contactPaths) = ApplyRecoveryAction(argumentsJson);
        if (ok && exported is not null)
        {
            // The key sheet's ONLY transit: this one-time message to
            // the companion window over the owner channel. It is not
            // in the action result below, not in the snapshot, not in
            // the audit log, and the Core keeps no copy.
            try
            {
                var sheetPayload = JsonSerializer.Serialize(new
                {
                    keySheet = exported.KeySheet,
                    deviceId = exported.DeviceId,
                    primaryPath,
                    contactPaths,
                });
                await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.RecoveryKeySheet, null, null, sheetPayload, null,
                    null, null, null, null, null), _cts.Token);
            }
            catch { /* window not connected: the export is audited; the owner re-exports to see a sheet */ }
        }
        await PushActionResultSafelyAsync("recovery", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    private async Task ApplySessionActionSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplySessionAction(argumentsJson);
        await PushActionResultSafelyAsync("session", ok, detail);
        _ = PushHostStateSafelyAsync();
    }

    private async Task ApplyEnrollmentRedeemSafelyAsync(string? argumentsJson)
    {
        var (ok, detail) = ApplyEnrollmentRedeem(argumentsJson);
        await PushActionResultSafelyAsync("enrollment_redeem", ok, detail);
        if (ok) _ = PushHostStateSafelyAsync();
    }

    private async Task PushOffboardBlastSafelyAsync(string? argumentsJson)
    {
        try
        {
            var blastJson = BuildOffboardBlastJson(argumentsJson);
            if (blastJson is null)
            {
                await PushActionResultSafelyAsync("roster_offboard_preview", false,
                    "no blast list (unknown scope or user)");
                return;
            }
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.RosterOffboardBlast, null, null, blastJson, null,
                null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"offboard_blast_push_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    /// <summary>Mint a Slice 1 enrollment code from the host window
    /// and send it back for one-time display, with its QR payload.
    /// Scope/group/transport are bound at mint (D22/D31) — the
    /// redeeming side can never widen them.</summary>
    private async Task PushEnrollmentCodeSafelyAsync(string? argumentsJson)
    {
        try
        {
            string scope = "local", groupId = "", groupName = "", mode = "inherit";
            string? mintedBy = null;
            string[] allowed = Array.Empty<string>();
            var ttl = EnrollmentService.DefaultCodeTtl;
            if (argumentsJson is not null)
            {
                using var doc = JsonDocument.Parse(argumentsJson);
                var root = doc.RootElement;
                scope = JsonStr(root, "scope") ?? scope;
                groupId = JsonStr(root, "groupId") ?? "";
                groupName = JsonStr(root, "groupName") ?? "";
                mode = JsonStr(root, "transportMode") ?? mode;
                mintedBy = JsonStr(root, "mintedByUserId");
                allowed = JsonStrArray(root, "allowedTransports");
                if (root.TryGetProperty("ttlMinutes", out var t) && t.ValueKind == JsonValueKind.Number)
                    ttl = TimeSpan.FromMinutes(Math.Clamp(t.GetDouble(), 1, 24 * 60));
            }
            var code = Enrollments.CreateEnrollmentCode(scope, groupId, groupName, ttl, mode, allowed, mintedBy);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"enrollment_code_minted_via_agent:{scope}:{groupId}", "SYSTEM", null));
            var payload = JsonSerializer.Serialize(new
            {
                code,
                qr = EnrollPayload.Build(code, scope, groupId),
                expiresUtc = (_options.Clock?.UtcNow ?? DateTimeOffset.UtcNow) + ttl,
                scope, groupId, groupName,
            });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.EnrollmentCodeMsg, null, null, payload, null,
                null, null, null, null, null), _cts.Token);
        }
        catch (Exception ex)
        {
            await PushActionResultSafelyAsync("enrollment_mint", false,
                $"mint refused ({ex.GetType().Name}: bad scope/group/mode)");
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"enrollment_mint_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    private async Task PushActionResultSafelyAsync(string action, bool ok, string detail)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new { action, ok, detail });
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.ActionResult, null, null, payload, null,
                null, null, null, null, null), _cts.Token);
        }
        catch { /* agent not connected: the act itself is already audited host-side */ }
    }

    /// <summary>STOP ends Slice 3 human sessions too (Block A
    /// wiring): while STOP is in force there is no live session of
    /// either kind. Each human session is stopped through the model's
    /// own STOP (host-side actor where one exists — acceptor or host
    /// participant — so the replay records host_stop), falling back
    /// to the trusted composition-root end for sessions whose host
    /// side is gone. Every ending is audited here as well.</summary>
    private void EndHumanSessionsOnStop(string source)
    {
        // The stream dies with the sessions (Block D): tear every
        // capture down now; the stream layer's per-call session
        // re-reads are the backstop that makes this race-free.
        try { _ = Stream.StopAllAsync(_cts.Token); } catch { }
        // Terminals die with the session too (Block F).
        try { Terminals.ReapEnded(); } catch { }
        try
        {
            foreach (var s in HumanSessions.ListSessions())
            {
                if (s.State == "ended") continue;
                var actor = s.AcceptedByUserId
                    ?? HumanSessions.ListParticipants(s.Id).FirstOrDefault(p => p.Role == "host")?.UserId;
                var stopped = actor is not null && HumanSessions.StopSession(s.Id, actor);
                if (!stopped) stopped = HumanSessions.EndSession(s.Id, null);
                try { Transports.ForgetLink(s.Id); } catch { }
                if (stopped)
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", null, null, null, null, null,
                        $"human_session_ended:{source}:{s.Id}", "SYSTEM", null));
            }
        }
        catch { /* the supervisor's STOP enforcement must never die of this sweep */ }
    }

    /// <summary>Vault one logon password sent from the laptop UI over
    /// the authenticated agent IPC (the vault panel — the only caller
    /// path; see UnlockService.VaultPasswordFromLaptop). The password
    /// is handed straight to the vault and is NEVER written to the
    /// audit log, a file, or a tool result; the audit records only
    /// that a seeding happened and the module's resulting state.
    /// Returns false for malformed payloads (ignored, never fatal).</summary>
    public async Task<bool> ApplyVaultFromLaptopAsync(string? argumentsJson)
    {
        if (argumentsJson is null) return false;
        try
        {
            string? password;
            using (var doc = JsonDocument.Parse(argumentsJson))
                password = doc.RootElement.TryGetProperty("password", out var p) ? p.GetString() : null;
            if (string.IsNullOrEmpty(password)) return false;
            Unlock.VaultPasswordFromLaptop(password);
            await Unlock.RefreshStateAsync(CancellationToken.None);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"vault_seeded_via_agent:state={Unlock.State}", "SYSTEM", null));
            await SendVaultStateAsync();
            return true;
        }
        catch { return false; /* malformed vault message: ignored, never fatal */ }
    }

    /// <summary>Wipe the vault at the laptop UI's request (same
    /// channel discipline as seeding). Audited as an event only.</summary>
    public async Task<bool> ApplyVaultWipeFromLaptopAsync()
    {
        try
        {
            Unlock.WipeVault();
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"vault_wiped_via_agent:state={Unlock.State}", "SYSTEM", null));
            await SendVaultStateAsync();
            return true;
        }
        catch { return false; }
    }

    /// <summary>Tell the laptop window the vault's current state (a
    /// state name only) so its status line reflects the Core's own
    /// record, not the window's guess.</summary>
    private async Task SendVaultStateAsync()
    {
        try
        {
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.VaultState, null, null, null, null,
                $"Credential vault: {Unlock.State}", null, null, null, null), CancellationToken.None);
        }
        catch { /* agent not connected: the state waits in the Core; the window re-reads on next vault action */ }
    }

    private IReadOnlySet<string> ReadApprovedGates()
    {
        // Plan approvals (DESIGN §6.7) — second-inspector C3 rewired the
        // trust path: the data-dir file is read ONCE at construction
        // (below), when only the installer / laptop UI has written it.
        // Runtime changes arrive only over the authenticated agent IPC
        // (the laptop UI is the approver; the message handler is in the
        // constructor). A tool running as SYSTEM editing the file
        // mid-run changes NOTHING — the self-serve approval loop is
        // closed. (A deliberately hostile SYSTEM principal remains
        // outside any in-host consent model; that is recorded honestly
        // in BUILD-REPORT rather than pretended away.)
        lock (_gatesLock) return new HashSet<string>(_approvedGates);
    }

    private void LoadStartupGates()
    {
        try
        {
            var path = Path.Combine(_options.DataDir, "approved-gates.json");
            if (!File.Exists(path)) return;
            var items = JsonSerializer.Deserialize<string[]>(File.ReadAllText(path)) ?? Array.Empty<string>();
            lock (_gatesLock) foreach (var item in items) _approvedGates.Add(item);
        }
        catch { /* a corrupt gates file approves nothing: fail closed */ }
    }

    public string StopFilePath => Path.Combine(_options.DataDir, "STOP");

    /// <summary>The host-config tunnel destination allowlist
    /// (Block H): the union of the ACP_TUNNEL_ALLOWLIST env var
    /// (the same host config the agent-tool TcpTunnelModule reads —
    /// one list governs both tunnel forms) and the data dir's
    /// tunnel-allowlist.json (a JSON array of "host:port" strings,
    /// the managed-list form an admin edits). NULL when neither
    /// source names an entry: not configured, and the session
    /// tunnel service's pivot blocklist remains the control.</summary>
    private static IReadOnlySet<string>? LoadTunnelAllowlist(string dataDir)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var env = Environment.GetEnvironmentVariable("ACP_TUNNEL_ALLOWLIST") ?? "";
        foreach (var e in env.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            set.Add(e);
        try
        {
            var path = Path.Combine(dataDir, "tunnel-allowlist.json");
            if (File.Exists(path))
            {
                var entries = JsonSerializer.Deserialize<string[]>(File.ReadAllText(path));
                if (entries is not null)
                    foreach (var e in entries)
                        if (!string.IsNullOrWhiteSpace(e)) set.Add(e.Trim());
            }
        }
        catch { /* an unreadable allowlist file contributes nothing — never a widening */ }
        return set.Count == 0 ? null : set;
    }

    /// <summary>Policy-change TEARDOWN driver (Block H — the D38
    /// F6/AF7 remainder, wiring half): run every G service's sweep
    /// for the loaded bundle's OWN scope (F2: a bundle governs
    /// only its scope), with "disabled" read from the bundle's
    /// three-state posture. Wake targets and second factors have
    /// no continuing live effect to tear down — wake is an act,
    /// factor verification re-consults the gate per act — so the
    /// sweep covers exactly the four continuing effects: calls,
    /// session surfaces, tunnels, transfer jobs. A non-empty sweep
    /// is chained-audited as one summary act.</summary>
    public int ApplyPolicyTeardown()
    {
        var enforcer = Enterprise.Enforcer;
        if (enforcer is null) return 0;
        var scopeId = enforcer.Bundle.ScopeId;
        Func<string, bool> disabled = key => Enterprise.FeatureState(key) == "disabled";
        var torn = 0;
        torn += HumanSessions.SweepPolicyTeardown(scopeId, disabled);
        torn += SessionTunnels.SweepPolicyTeardown(scopeId, disabled);
        torn += StandaloneTransfers.SweepPolicyTeardown(scopeId, disabled);
        if (torn > 0)
            Enterprise.AppendServiceAudit("policy_teardown_sweep", "policy",
                $"a policy change tore down {torn} live feature effect(s) in scope {scopeId} " +
                "(live calls, session surfaces, tunnels, transfer jobs whose features the new bundle disables)");
        return torn;
    }

    /// <summary>Consume the self-restart watchdog's outcome file
    /// (Block H): the watchdog ran while this Core was down, so its
    /// record lands in the enterprise chained audit NOW, at the
    /// first start that can hold it — and anything but a clean
    /// restart raises an alert. The file is deleted after a
    /// successful consume so the outcome is recorded exactly once;
    /// a failed consume leaves it for the next start.</summary>
    private void ConsumeRestartOutcome()
    {
        // EVERY pending outcome is consumed (Block H D38 fix
        // F11): outcomes are per-outcome files in the outcomes
        // directory — an outcome for a non-Core service can wait
        // there while this Core keeps running and is drained at
        // this start, never overwritten by a later outcome. The
        // legacy single file mirrors the newest directory outcome
        // and is consumed only when the directory is empty (a
        // pre-F11 watchdog's last write), so nothing double-records.
        var files = new List<string>();
        var dir = Services.FileRestartOutcomeSink.OutcomesDir(_options.DataDir);
        if (Directory.Exists(dir))
            files.AddRange(Directory.EnumerateFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal));
        var legacy = Services.FileRestartOutcomeSink.OutcomePath(_options.DataDir);
        if (files.Count == 0 && File.Exists(legacy)) files.Add(legacy);
        foreach (var path in files)
        {
            var outcome = JsonSerializer.Deserialize<Services.RestartOutcome>(File.ReadAllText(path));
            if (outcome is null) { File.Delete(path); continue; }
            Enterprise.AppendServiceAudit("service_restart_outcome", "restart-watchdog",
                $"service {outcome.ServiceName} restart outcome: {outcome.State} — {outcome.Detail} " +
                $"(start attempts {outcome.StartAttempts}, rollback {(outcome.RollbackUsed ? "USED" : "not used")}, finished {outcome.FinishedUtc:O})");
            if (outcome.State != "restarted")
                Enterprise.Alerts.Raise("service_restart",
                    $"service restart of {outcome.ServiceName} ended {outcome.State}: {outcome.Detail}", DateTimeOffset.UtcNow);
            File.Delete(path);
        }
    }

    /// <summary>W107 (W106-verified C4a): ingest pending
    /// duplicate-start refusal records into the audit chain of
    /// record — the ConsumeRestartOutcome shape applied to the
    /// single-instance guard. A refused second Core cannot append
    /// to the chain itself (W93: concurrent chain appends under
    /// contention are unsafe), so it leaves a tamper-evident
    /// record file; the RUNNING Core — the chain's single writer —
    /// appends each record here as the refusal event it is,
    /// carrying the refused process's own fields VERBATIM plus the
    /// ingestion source and the record's hash state, and deletes
    /// the file so each refusal is ingested exactly once. An
    /// unparseable record is left in place (never guessed at) and
    /// the failure is audited. Called at StartAsync and on the
    /// supervisor's ~30 s beat, so a duplicate refused while this
    /// Core is already running still lands in the chain.</summary>
    public int ConsumeDuplicateStartRecords()
    {
        var ingested = 0;
        foreach (var path in CoreInstanceLock.FindDuplicateStartRecords(_options.DataDir))
        {
            var record = CoreInstanceLock.ReadDuplicateStartRecord(path);
            if (record is null)
            {
                try
                {
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                        $"duplicate_core_start_record_unreadable:{Path.GetFileName(path)} — left in place, not ingested", "SYSTEM", null));
                }
                catch { }
                continue;
            }
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"duplicate_core_start_refused:{record.Line} | {record.FieldsLine} | " +
                $"ingested by the running Core from {Path.GetFileName(path)}; record sha256 {record.HashState}" +
                (record.RecordSha256 is not null ? $" ({record.RecordSha256})" : ""),
                "SYSTEM", null));
            File.Delete(path);
            ingested++;
        }
        return ingested;
    }

    /// <summary>One RMM hub duty cycle (closing integration, item 2):
    /// run the endpoint monitor, feed its sample to anomaly detection
    /// (RMM-27), run a baseline-drift cycle (RMM-19 duty), ingest the
    /// monitor's health report into the hub ingest (RMM-01 BuildReport
    /// → HubHealthIngest), refresh the hub's known-managed MAC set for
    /// discovery, and sweep device-down. Callable by the host's duty
    /// loop; each sub-step is policy-gated inside its own service.</summary>
    public void RunMonitorDutyCycle()
    {
        var now = DateTimeOffset.UtcNow;
        var cycle = Monitor.RunCycle();
        if (cycle.Sample is not null)
        {
            try { AnomalyDetection.Observe(cycle.Sample); } catch { /* anomaly never breaks the monitor cycle */ }
        }
        try { BaselineDrift.RunCycle(Identity.DeviceId); } catch { /* drift duty is best-effort per cycle */ }
        try { EndpointSecurity.RunDetectionCycle(); } catch { /* endpoint-security duty is best-effort per cycle; its own refusals are chained inside the service */ }
        try { HubHealth.Ingest(Monitor.BuildReport(), now); } catch { }
        // SetKnownManagedMacs: the seam is wired (NetworkDiscovery
        // property above); the MAC source is a remainder — inventory
        // records carry no MAC field in the RMM-04 model, so no honest
        // source exists in this Core yet (named in the integration log).
        try { HubHealth.SweepDeviceDown(now); } catch { }
    }

    public async Task StartAsync(CancellationToken ct)
    {
        // Post-mortem first: read how the previous run ended BEFORE this
        // run's marker overwrites it (DESIGN §4.4).
        var previous = Marker.ReadPreviousRun();
        State.SetPreviousRun(previous);
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
            previous is null ? "core_started_first_run" : $"core_started; {previous.Characterization}", "SYSTEM", null));
        Marker.Beat(State.ComputeState(), "core started");

        foreach (var err in _pluginErrors)
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"plugin_load_failed:{err}", "SYSTEM", null));
        // Self-restart outcome (Block H): if the previous run was
        // stopped by the restart watchdog, its outcome file is
        // waiting — consume it into the ENTERPRISE chained audit
        // (the permanent record the drill-era restart never made)
        // and raise an alert for anything but a clean restart.
        try { ConsumeRestartOutcome(); }
        catch (Exception ex) { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"restart_outcome_consume_error:{ex.GetType().Name}", "SYSTEM", null)); }
        // W107 (C4a): duplicate-start refusals that landed before
        // this start (or while no Core was running) join the chain
        // now; the supervisor beat keeps ingesting while we run.
        try { ConsumeDuplicateStartRecords(); }
        catch (Exception ex) { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"duplicate_start_consume_error:{ex.GetType().Name}", "SYSTEM", null)); }
        // W113: a start that proceeded on the operator's one-time
        // liveness override says so IN THE CHAIN — the override
        // bypassed a death proof, and that fact is itself part of
        // the record, never a silent hole in it.
        if (_livenessOverrideAuditDetail is not null)
        {
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"core_started_on_operator_liveness_override:{_livenessOverrideAuditDetail}", "SYSTEM", null));
        }
        // Safe Mode ride: if the previous boot set safeboot for us, this
        // boot clears it FIRST THING (SafeModeOrchestrator contract).
        try { await SafeMode.OnBootAsync(_cts.Token); }
        catch (Exception ex) { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"safemode_onboot_error:{ex.GetType().Name}", "SYSTEM", null)); }

        // Settle the unlock module's state from the facts at boot so the
        // laptop window and state reports tell the truth (Ready /
        // VaultEmpty / Hello-only) without waiting for a vault action,
        // and leave the settled state in the audit as boot evidence.
        try
        {
            await Unlock.RefreshStateAsync(ct);
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                $"unlock_state_at_boot:{Unlock.State}", "SYSTEM", null));
        }
        catch (Exception ex) { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"unlock_state_refresh_error:{ex.GetType().Name}", "SYSTEM", null)); }

        // Installer bootstrap pairing: the installer drops
        // bootstrap-pairing.json before first start; the Core mints the
        // one-time code and leaves it in pairing-code.txt for the owner to
        // read off HIS laptop and confirm — the code is born on the
        // host and shown on the host, exactly as SPEC §5.2 requires.
        var bootstrapPath = Path.Combine(_options.DataDir, "bootstrap-pairing.json");
        if (File.Exists(bootstrapPath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(bootstrapPath));
                var agentName = doc.RootElement.TryGetProperty("agent_name", out var an) ? an.GetString() ?? "agent" : "agent";
                var ttlMinutes = doc.RootElement.TryGetProperty("ttl_minutes", out var ttl) ? ttl.GetInt32() : 30;
                var code = Pairings.CreatePairingCode(agentName, TimeSpan.FromMinutes(ttlMinutes));
                File.WriteAllText(Path.Combine(_options.DataDir, "pairing-code.txt"),
                    $"ACP pairing code for {agentName}: {code} (valid {ttlMinutes} minutes, one use)");
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "bootstrap_pairing_code_minted", "SYSTEM", null));
            }
            catch (Exception ex) { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"bootstrap_pairing_error:{ex.GetType().Name}", "SYSTEM", null)); }
            try { File.Delete(bootstrapPath); } catch { }
        }

        _ipcTask = Ipc.RunAsync(_cts.Token);
        _supervisorTask = SupervisorLoopAsync(_cts.Token);
        await Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken ct)
    {
        // Last-word protocol: a graceful stop announces itself.
        Marker.AnnounceDeparture(State.ComputeState(), "core stopping gracefully");
        Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "core_stopping", "SYSTEM", null));
        _cts.Cancel();
        try { if (_supervisorTask is not null) await _supervisorTask; } catch (OperationCanceledException) { }
        try { if (_ipcTask is not null) await _ipcTask; } catch (OperationCanceledException) { }
        await LaneHosts.DisposeAsync();
        // W20: clean shutdown removes the token file — a dead boot's
        // secret must not outlive the Core that minted it.
        Services.IpcTokenFileChannel.Remove(_options.DataDir);
        Marker.MarkCleanShutdown(State.ComputeState());
        // FR-124 / W95: this run has ended (cleanly, its marker
        // says so) — release the single-instance lock so the next
        // Core for this data dir may start. DisposeAsync releases
        // too; Dispose on the lock is idempotent.
        InstanceLock.Dispose();
    }

    private async Task SupervisorLoopAsync(CancellationToken ct)
    {
        var lastBeat = DateTimeOffset.MinValue;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                // STOP file kill switch (DESIGN §6.6): checked every tick,
                // enforced host-side before the next call.
                var stopPresent = File.Exists(StopFilePath);
                if (stopPresent != State.StopInForce)
                {
                    State.SetStopFilePresent(stopPresent);
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                        stopPresent ? "stop_file_engaged" : "stop_file_cleared", "SYSTEM", null));
                    if (stopPresent && Sessions.Current is not null)
                    {
                        Sessions.Stop();
                        State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
                        _ = NotifyReleaseInputsSafelyAsync(); // U7: session end releases held input
                    }
                    if (stopPresent) EndHumanSessionsOnStop("stop_file");
                }

                // Lanes: the state machine decides; the manager acts.
                foreach (var lane in new[] { LaneKind.Tailscale, LaneKind.Lan })
                {
                    foreach (var transition in Lanes.Tick(lane))
                    {
                        var laneName = lane.ToString();
                        if (transition.Action is "bind" or "rebind")
                        {
                            if (transition.Action == "rebind") await LaneHosts.StopLaneAsync(laneName).WaitAsync(TimeSpan.FromSeconds(10), ct);
                            var ok = await LaneHosts.StartLaneAsync(laneName, transition.Address!, ct).WaitAsync(TimeSpan.FromSeconds(15), ct);
                            Lanes.ReportBindResult(lane, ok);
                            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                                ok ? $"lane_bound:{lane}:{transition.Address}" : $"lane_bind_failed:{lane}:{transition.Address}", "SYSTEM", null));
                        }
                        else if (transition.Action == "unbind")
                        {
                            await LaneHosts.StopLaneAsync(laneName).WaitAsync(TimeSpan.FromSeconds(10), ct);
                        }
                    }
                }
                if (_options.IncludeLoopbackLane && !LaneHosts.RunningLanes.Contains("loopback"))
                    await LaneHosts.StartLaneAsync("loopback", "127.0.0.1", ct);

                // STOP ends the live session, whatever engaged it
                // (M1, 2026-11-17): panic_stop's own descriptor always
                // promised "sessions end", but only the STOP-file path
                // actually ended one — a banner STOP left the session
                // record alive behind the policy block. One place,
                // every source: while STOP is in force there is no
                // session; the agent starts a new one after the owner
                // clears the block.
                if (State.StopInForce && Sessions.Current is not null)
                {
                    var endedByStop = Sessions.Stop();
                    State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", endedByStop?.PairingId, endedByStop?.ActorAgentName, null, null, null, "session_ended:user_stop", null, null));
                    // BD-WIN-CORE-2/F3: STOP tears down every tunnel forward.
                    try { Tunnels.StopAll(); } catch { }
                    // U7: STOP also lets go of any held key/button immediately.
                    _ = NotifyReleaseInputsSafelyAsync();
                }
                // STOP from presence (or any source) ends Slice 3
                // human sessions too — one STOP, every session kind.
                if (State.StopInForce) EndHumanSessionsOnStop("user_stop");

                // Presence: push the COMPLETE truth (session, agent
                // name, STOP) whenever any input to it changes —
                // including the agent (re)connecting, so a restarted
                // agent converges on reality instead of painting its
                // own guess (ACP DNA — presence can never lag the
                // truth; M1 rework after the 2026-11-17 stuck banner,
                // whose push left the name field unset entirely).
                var cur = Sessions.Current;
                if (cur is not null) _lastActingAgentName = cur.ActorAgentName;
                // Slice 3 human sessions feed presence too (Block A):
                // the primary live human session is part of the key,
                // so its start/state/end pushes presence exactly like
                // an agent session's does.
                var humanPrimary = SessionPicture.PrimaryLive(HumanSessions, Roster, DateTimeOffset.UtcNow);
                if (cur is null && humanPrimary is not null) _lastActingAgentName = humanPrimary.InitiatorName;
                // The 5-second bucket while a session is live keeps
                // the payload's sessionSeconds/actions fresh for the
                // companion window's timer/counter (M4) without a
                // per-second push; state changes still push instantly.
                var bucket = cur is not null
                    ? ((long)(DateTimeOffset.UtcNow - cur.StartedUtc).TotalSeconds / 5).ToString()
                    : humanPrimary is not null ? (humanPrimary.Seconds / 5).ToString() : "";
                var presenceKey = $"{cur?.Id ?? "-"}|{humanPrimary?.Id ?? "-"}:{humanPrimary?.State ?? "-"}|{State.StopInForce}|{State.Session.AgentConnected}|{bucket}";
                if (presenceKey != _lastPresenceKey)
                {
                    _lastPresenceKey = presenceKey;
                    _ = PushPresenceSafelyAsync(cur, State.StopInForce);
                }

                // Watchdog.
                Watchdog.Tick(DateTimeOffset.UtcNow);

                // Session backstops (idle timeout / time box, SPEC §7.8).
                if (Sessions.ExpiryReason(DateTimeOffset.UtcNow) is { } reason)
                {
                    var ended = Sessions.Stop();
                    State.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
                    Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", ended?.PairingId, ended?.ActorAgentName, null, null, null, $"session_ended:{reason}", null, null));
                    // BD-WIN-CORE-2/F3: a session that ends takes its pairing's forwards with it.
                    if (ended?.PairingId is { } endedPairing) try { Tunnels.StopForPairing(endedPairing); } catch { }
                    // U7: an expired session's held input is released too.
                    if (ended is not null) _ = NotifyReleaseInputsSafelyAsync();
                }

                // Heartbeat: file artifact + marker beat every ~30 s.
                if (DateTimeOffset.UtcNow - lastBeat > TimeSpan.FromSeconds(30))
                {
                    lastBeat = DateTimeOffset.UtcNow;
                    // W107 (C4a): a duplicate refused while THIS
                    // Core runs leaves its record in the data dir;
                    // ingest it into the chain on this beat.
                    try { ConsumeDuplicateStartRecords(); } catch { /* audited inside StartAsync's call; a beat failure must not kill the supervisor */ }
                    var heartbeat = State.BuildHeartbeat();
                    await File.WriteAllTextAsync(Path.Combine(_options.DataDir, "heartbeat.json"),
                        JsonSerializer.Serialize(heartbeat, new JsonSerializerOptions { WriteIndented = true }), ct);
                    Marker.Beat(State.ComputeState());
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                // The supervisor must not die of its own tick: log and continue.
                Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"supervisor_tick_error:{ex.GetType().Name}", "SYSTEM", null));
            }

            try { await Task.Delay(_options.SupervisorPeriod, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        // FR-124 / W95: disposing the runtime ends this instance —
        // release the single-instance lock (see StopAsync).
        InstanceLock.Dispose();
        Services.IpcTokenFileChannel.Remove(_options.DataDir);
        try { LanListener.Dispose(); } catch { }
        try { HubListener.Dispose(); } catch { }
        await LaneHosts.DisposeAsync();
        Ipc.Dispose();
        _cts.Dispose();
    }

    /// <summary>IAgentRestarter glue: dropping the IPC connection is the
    /// restart act — the watchdog sees the stale heartbeat and relaunches
    /// the agent. Elevation is recorded and effected the same way (the
    /// relaunched agent starts through the logon task's principal; a
    /// true token elevation is laptop-gate work, named in the report).</summary>
    /// <summary>Push the complete presence truth to the agent: one
    /// message carrying the session flag, the acting agent's NAME
    /// (its own field — the 2026-11-17 banner bug was this method's
    /// predecessor leaving the name unset so the agent rendered
    /// "An agent"), the STOP flag, and the intent line. The agent
    /// reconciles its state machine from this directive; it never
    /// has to infer state from which fields happen to be populated.</summary>
    /// <summary>U1: push the resolved clipboard policy to the
    /// session agent's desktop engine (the second wall at the
    /// clipboard path). When the policy layer is toggled OFF the
    /// push carries ClipboardPolicy.Legacy explicitly — standing
    /// down is stated, never a silent gap. Best-effort: with no
    /// agent connected the push is dropped and the next auth /
    /// presence push carries it; the choke point enforces the same
    /// policy per call in the meantime.</summary>
    private async Task PushClipboardPolicySafelyAsync()
    {
        try
        {
            var policy = Sessions.ResolveClipboardPolicy() ?? ClipboardPolicy.Legacy;
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.ClipboardPolicy, null, null, policy.ToIpcJson(), null,
                null, null, null, null, null), _cts.Token);
        }
        catch { /* no agent connected — see summary */ }
    }

    private async Task PushPresenceSafelyAsync(SessionRecord? session, bool stopInForce)
    {
        // Fire-and-forget, but OBSERVED: a failed presence push is
        // audited, never an unobserved task exception.
        try
        {
            // While STOP is in force the session record is already
            // gone (the supervisor ends it), so the blocked banner
            // takes the name from the last acting session — "Muse
            // is blocked", never a nameless block.
            var agentName = session?.ActorAgentName
                ?? (stopInForce ? _lastActingAgentName : null)
                ?? State.Session.ActingAgentName;
            // Slice 3 (Block A): with no agent session live, presence
            // derives from the primary live HUMAN session — the box
            // names its initiator, the seconds are its elapsed time,
            // the action count is its chat + file activity. Still
            // exactly three elements; only the source of truth grew.
            var human = session is null && !stopInForce
                ? SessionPicture.PrimaryLive(HumanSessions, Roster, DateTimeOffset.UtcNow)
                : null;
            if (human is not null) agentName = human.InitiatorName;
            var payload = JsonSerializer.Serialize(new
            {
                active = session is not null || human is not null,
                agent = agentName,
                stopInForce,
                // Companion-window facts (M4): elapsed + action count,
                // refreshed by the supervisor's 5 s bucket push.
                seconds = session is not null
                    ? Math.Max(0, (long)(DateTimeOffset.UtcNow - session.StartedUtc).TotalSeconds)
                    : human?.Seconds ?? 0,
                actions = session is not null ? Sessions.ActionCount : human?.Actions ?? 0,
                // D35 fold-in (Block F): the participant roster rides
                // INSIDE the presence box — the floor holder named,
                // every participant listed with role/floor/transport,
                // and whether a terminal is open on the session. The
                // composition stays three elements; the box's CONTENT
                // carries the roster, as D35 specifies.
                floorHolder = human?.FloorHolderName,
                transport = human is null ? null : HumanSessions.GetSession(human.Id)?.TransportRung,
                terminalOpen = human is not null && Terminals.OpenTerminalFor(human.Id) is not null,
                participants = human?.Participants.Select(p => new
                {
                    name = p.Name, role = p.Role, floor = p.Floor, transport = p.Transport,
                }).ToArray(),
            });
            var narration = session is not null
                ? $"{agentName} is working on your laptop"
                : human is not null
                    ? $"{human.InitiatorName} is in a {(human.Kind == "attended" ? "attended" : "remote")} session on this PC" +
                      (human.IsRecording ? " · recording" : "")
                    : null;
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.Presence, null, null, payload, null,
                session is not null || stopInForce ? "on" : "off", null, null, null, narration,
                AgentName: agentName), _cts.Token);
            // U1: every presence push also refreshes the agent's
            // clipboard policy, so an admitted policy document lands
            // on the engine at the next session-state change at the
            // latest (the choke point resolves per call regardless).
            await PushClipboardPolicySafelyAsync();
            // FR-120 (W73): every presence push also refreshes the
            // agent's takeover fleet defaults, so an admitted
            // policy document lands at the next session-state
            // change at the latest.
            await PushTakeoverDefaultsSafelyAsync();
        }
        catch (Exception ex)
        {
            try { Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, $"presence_notify_failed:{ex.GetType().Name}", "SYSTEM", null)); } catch { }
        }
    }

    /// <summary>FR-120 (W73): push the resolved takeover fleet
    /// defaults to the session agent. When the policy layer is
    /// toggled OFF the push carries NO defaults explicitly —
    /// standing down is stated, never a silent gap. Best-effort:
    /// with no agent connected the push is dropped and the next
    /// auth / presence push carries it.</summary>
    private async Task PushTakeoverDefaultsSafelyAsync()
    {
        try
        {
            var facts = Shared.ManagementPolicy.StaticDeviceFacts.Of(Identity.DeviceId, "");
            var defaults = ManagementPolicies.IsEnabled(facts, TakeoverPolicyKeys.FeatureToggle)
                ? TakeoverFleetDefaults.FromEffective(ManagementPolicies.ComputeEffective(facts))
                : TakeoverFleetDefaults.None;
            await Ipc.NotifyAgentAsync(new IpcMessage(IpcKinds.TakeoverDefaults, null, null, defaults.ToIpcJson(), null,
                null, null, null, null, null), _cts.Token);
        }
        catch { /* no agent connected — see summary */ }
    }

    /// <summary>FR-120 (W73): append one agent-reported takeover
    /// fact to the audit chain — the agent session's record. Kind
    /// and actor are coerced through the closed vocabularies.</summary>
    private void RecordTakeoverEvent(string? payloadJson)
    {
        string kind = "unrecognized", actor = "unrecognized", detail = "";
        try
        {
            if (payloadJson is not null)
            {
                using var doc = JsonDocument.Parse(payloadJson);
                var root = doc.RootElement;
                if (root.TryGetProperty("kind", out var k) && k.GetString() is { } ks &&
                    ks is Shared.Presence.TakeoverRecordKinds.ModesAtStart or Shared.Presence.TakeoverRecordKinds.ModeChanged
                        or Shared.Presence.TakeoverRecordKinds.Yield or Shared.Presence.TakeoverRecordKinds.HandBack
                        or Shared.Presence.TakeoverRecordKinds.Hotkey)
                    kind = ks;
                if (root.TryGetProperty("actor", out var a) && a.GetString() is { } @as &&
                    @as is Shared.Presence.TakeoverActors.OwnerLocal or Shared.Presence.TakeoverActors.InSession
                        or Shared.Presence.TakeoverActors.OwnerHandBackControl or Shared.Presence.TakeoverActors.OwnerGateApproval
                        or Shared.Presence.TakeoverActors.OwnerHotkey or Shared.Presence.TakeoverActors.LocalInput)
                    actor = @as;
                if (root.TryGetProperty("detail", out var d) && d.GetString() is { } ds)
                    detail = ds.Length > 300 ? ds[..300] : ds;
            }
        }
        catch { /* malformed report: the unrecognized entry below is the honest record */ }
        try
        {
            Audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "session", null,
                State.Session.ActingAgentName, "takeover", kind,
                System.Text.Json.JsonSerializer.Serialize(new { actor, detail }),
                "recorded", "Owner", null));
        }
        catch { }
    }

    private sealed class AgentRestarter : IAgentRestarter
    {
        private readonly AgentIpcServer _ipc;
        private readonly FileAuditLog _audit;
        public AgentRestarter(AgentIpcServer ipc, FileAuditLog audit) { _ipc = ipc; _audit = audit; }
        public void RestartAgent()
        {
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "agent_restart_requested", "SYSTEM", null));
            _ipc.DropConnection();
        }
        public void RequestElevation()
        {
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "agent_elevation_requested", "SYSTEM", null));
            _ipc.DropConnection();
        }
    }
}
