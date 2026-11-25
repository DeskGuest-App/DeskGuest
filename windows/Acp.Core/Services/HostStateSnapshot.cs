using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Security;
using Acp.Shared.Sessions;

namespace Acp.Core.Services;

/// <summary>
/// The host-state snapshot the companion window renders (M4,
/// 2026-11-17): pairings, gate approvals, session facts, and the
/// audit tail, shaped as one JSON document. Pure shaping over plain
/// inputs so the format is unit-testable without a runtime — the
/// window must only ever display facts the Core actually holds, and
/// this document is the whole of what it gets. It contains NO
/// secrets: pairing tokens are never included (only names, scopes,
/// states), and audit arguments arrive already redacted from the log
/// itself.
/// </summary>
public static class HostStateSnapshot
{
    public sealed record SessionFacts(
        bool Active, string? AgentName, long Seconds, int Actions, string? Intent);

    // ---- Slice 2 roster facts (Block A wiring) ---------------------
    // Directory facts only: ids, names, kinds, membership, rights.
    // Enrolled devices carry NO public key here — the window displays
    // identity (device id, name, group), never key material, even
    // public key material (least surface, host_state pattern).
    public sealed record RosterUserFact(string Id, string DisplayName, string Kind, string? PairedByUserId, bool Suspended);
    public sealed record RosterUserGroupFact(string Id, string Name, IReadOnlyList<string> Members, IReadOnlyList<string> Admins);
    public sealed record RosterDeviceFact(string DeviceId, string DisplayName, string GroupId, string GroupName, string Scope, DateTimeOffset EnrolledUtc, bool Revoked, string TransportMode, string Sas = "", bool SasConfirmed = false);
    public sealed record RosterDeviceGroupFact(string Id, string Name, IReadOnlyList<string> TransportSet, IReadOnlyList<string> DeviceIds, IReadOnlyList<RosterDeviceFact> Devices);
    public sealed record RosterGrantFact(string UserGroupId, string DeviceGroupId, IReadOnlyList<string> Rights);
    public sealed record RosterScopeFact(
        string Id, string Kind, string Name, IReadOnlyList<string> TransportCeiling,
        IReadOnlyList<string> CompanyAdminIds, IReadOnlyList<RosterUserFact> Users,
        IReadOnlyList<RosterUserGroupFact> UserGroups, IReadOnlyList<RosterDeviceGroupFact> DeviceGroups,
        IReadOnlyList<RosterGrantFact> Grants);

    /// <summary>The endpoint's OWN view (D2), shaped for the host
    /// window when it renders this machine as an endpoint: only this
    /// device's record and the operators derived from its receipts.
    /// Structurally incapable of naming another device.</summary>
    public sealed record EndpointFact(
        RosterDeviceFact Device,
        IReadOnlyList<EndpointOperatorFact> AllowedOperators,
        int ReceiptCount);
    public sealed record EndpointOperatorFact(string EnrollerName, string EnrollerDeviceId, string Scope, string GroupName, DateTimeOffset EnrolledUtc);

    // ---- Transport core facts (Block C part 1) ---------------------
    // The failover engine's recent events + the LAN listener's state.
    // Facts only: rung ids, event kinds, session ids — no addresses
    // beyond the listener's own port, no key material, ever.
    public sealed record TransportEventFact(string Kind, string? Rung, string Detail, string? FromSessionId, string? ToSessionId);
    public sealed record TransportFact(
        bool LanListening, int LanPort, int LanAccepted, int LanRefused,
        IReadOnlyList<TransportEventFact> Events,
        // Block C part 3: hub listener (same enrollment handshake,
        // bound to the mesh address) + mesh rung setup state.
        bool HubListening = false, int HubPort = 0, int HubAccepted = 0, int HubRefused = 0,
        string MeshSetupStage = "NotStarted", string MeshSetupDetail = "");

    // ---- Enterprise facts (Block F wiring of Block E) --------------
    // Policy/audit/break-glass TRUTH from the live EnterpriseService:
    // the loaded policy's state, the chained audit's verdict, alert
    // count, and whether a break-glass rotation is pending. Facts
    // only — no bundle contents, no secrets, no holder material.
    public sealed record EnterpriseFact(
        string PolicyState,
        bool PolicyLoaded,
        bool ChainOk,
        string ChainSummary,
        int AlertCount,
        bool BreakGlassRotationRequired,
        string RealIdpBoundary,
        // W43 (F2b): the W35/W36 posture-audit states, carried on
        // the Core's existing status surface so a named FAILED
        // state is observable live without chain access. States
        // only — no posture contents, no key material.
        string PointerSigningPostureAuditState = "not-attempted",
        string UpdateSigningPostureAuditState = "not-attempted",
        // W45: the Core's install-root anchor-marker advance state
        // (round-9 staged-pointer freshness) — a named FAILED
        // advance rides here beside the posture-audit states.
        string AnchorMarkerState = "not-composed");

    // ---- Block G facts (2026-11-20) --------------------------------
    // The completeness-sweep services' truth: counts only, plus the
    // eight TOTAL POLICY CONTROL feature postures read from the
    // loaded bundle ("allowed" when none is loaded). No MACs, no
    // job names, no factor material — counts and postures, never
    // contents.
    public sealed record BlockGFact(
        int WakeTargets,
        int StandaloneJobsLive,
        int TotpEnrollmentsActive,
        int PasskeysRegistered,
        int SessionTunnelsOpen,
        IReadOnlyDictionary<string, string> FeatureStates);

    // ---- Mesh facts (Block H tray fix) ------------------------------
    // The mesh companion's truth (MeshService.CurrentState + phone
    // facts), carried in the snapshot so EVERY agent surface — the
    // host window AND the tray popup — reads mesh state from the
    // one document the Core actually pushes. The popup previously
    // fetched http://127.0.0.1:8741/mesh/state itself, but the
    // loopback lane is dev/tests-only (CoreOptions.
    // IncludeLoopbackLane defaults false), so in production the
    // fetch could never succeed and the popup permanently read
    // "state unavailable" while the window showed live state.
    public sealed record MeshFact(string State, string? PhoneName, bool PhoneWatching);

    // ---- C20 recovery facts (2026-11-22 wiring) ----------------------
    // The recovery surface's truth for the host window: this device's
    // id, when the owner last exported, and the last restore's
    // outcome counts. Facts only — never a blob, never a key sheet,
    // never a passphrase (the sheet transits ONLY the one-time
    // RecoveryKeySheet IPC message at export).
    // ---- W122 / N22 inbox facts -----------------------------------
    // The unified inbox's index over S13's ONE thread store, per
    // pairing: agent messages beyond the owner's seen cursor,
    // order cards still pending the owner's answer, last activity,
    // and the pending cards themselves (oldest first) so the inbox
    // can surface one through the S12 gate sheet — the same owner
    // channel the thread push already uses for card bytes. Counts
    // and card facts only; message BODIES never ride the snapshot.
    public sealed record ChatPendingOrderFact(
        string Id, string Tool, string? GateClass, string ArgumentsJson,
        string Title, string TargetDevice, long CreatedAtMs);
    public sealed record ChatThreadFact(
        string PairingId, int UnreadMessages, int PendingOrders, long LastActivityMs,
        IReadOnlyList<ChatPendingOrderFact> PendingOrderList);

    public sealed record RecoveryFact(
        string DeviceId,
        DateTimeOffset? LastExportUtc,
        DateTimeOffset? LastRestoreUtc,
        string? LastRestoredDeviceId,
        int LastRestorePairings,
        int LastRestoreRosterEntries);

    // ---- FR-134 / item (16) Terms facts -----------------------------
    // The Terms the Core currently serves (version + SHA-256 of the
    // exact text). Carried in the snapshot so each pairing's
    // acknowledgment state can be computed where the pairing facts
    // are serialized: a pairing whose recorded ack hash differs
    // from this hash is "Terms update pending" on its card — the
    // owner sees why the agent is session-locked without lifting
    // a finger.
    public sealed record TermsFact(string Version, string Sha256);

    public static string Build(
        string coreVersion,
        string machineName,
        int port,
        IReadOnlyCollection<string> runningLanes,
        bool agentConnected,
        bool desktopUnlocked,
        bool userStopInForce,
        SessionFacts session,
        IReadOnlyList<Pairing> pairings,
        IReadOnlyCollection<string> gatedClasses,
        IReadOnlySet<string> approvedGates,
        IReadOnlyList<AuditEntry> auditTail,
        IReadOnlyList<RosterScopeFact>? roster = null,
        IReadOnlyList<HumanSessionFact>? humanSessions = null,
        EndpointFact? endpoint = null,
        TransportFact? transport = null,
        EnterpriseFact? enterprise = null,
        BlockGFact? blockG = null,
        MeshFact? mesh = null,
        // U5: the FULL per-agent data-flow report. This snapshot is
        // the owner's own surface (host window / mesh state the
        // owner's phone reads) — the only place every pairing's
        // flows appear side by side. Agent-callable surfaces get
        // their own pairing's slice only (SessionStatusModule).
        DataFlowReport? dataFlows = null,
        RecoveryFact? recovery = null,
        // W8: the live event watches (EventSubscriptions.ListAll) —
        // a standing watch channel must be visible on the owner's
        // presence surface; until this wiring the store had no
        // snapshot section and ListAll had no UI rendering.
        IReadOnlyList<EventWatch>? eventWatches = null,
        // FR-113 (W65): the Core's EFFECTIVE file roots (configured
        // ACP_FILE_ROOTS, or the staging-only fallback) so the
        // Guardrails label is generated from the configuration in
        // force, never hard-coded.
        IReadOnlyList<string>? fileRoots = null,
        // W97 / S09(b): each pairing's LIVE last-seen connection
        // (rung + when, this run only) from PairingService — the
        // card's "actually on" label reads this, never a stored
        // claim. Null lookup (older embedders) = no rung fields.
        Func<string, (string Rung, DateTimeOffset AtUtc)?>? lastConnection = null,
        // W122 / N22: the inbox index over the one chat store,
        // computed by the Core from AgentChatStore + ChatOrderStore
        // + the owner's seen cursors. Null (older embedders) = no
        // chatThreads section; the window then shows no inbox.
        IReadOnlyList<ChatThreadFact>? chatThreads = null,
        // FR-134 / item (16): the currently served Terms. Null
        // (older embedders) = no Terms fields on the pairing rows;
        // the window then shows no Terms state, as before.
        TermsFact? terms = null)
    {
        var doc = new
        {
            coreVersion,
            machineName,
            port,
            fileRoots = (fileRoots ?? Array.Empty<string>()).ToArray(),
            lanes = runningLanes.OrderBy(l => l, StringComparer.Ordinal).ToArray(),
            agentConnected,
            desktopUnlocked,
            userStop = userStopInForce,
            session = new
            {
                active = session.Active,
                agent = session.AgentName,
                seconds = session.Seconds,
                actions = session.Actions,
                intent = session.Intent,
            },
            pairings = pairings.Select(p => new
            {
                id = p.Id,
                name = p.AgentName,
                scopes = p.Scopes.OrderBy(s => s, StringComparer.Ordinal).ToArray(),
                createdUtc = p.CreatedUtc,
                expiresUtc = p.ExpiresUtc,
                revoked = p.Revoked,
                // W97 / S09(b): the connection-path setting + the
                // LIVE current rung (this run's last authenticated
                // arrival; null = has not connected since the Core
                // started — the card says exactly that).
                connectionMode = p.EffectiveConnection.Mode.ToString(),
                connectionRungs = p.EffectiveConnection.AllowedOrEmpty.OrderBy(s => s, StringComparer.Ordinal).ToArray(),
                connectionPin = p.EffectiveConnection.PinOrNull,
                currentRung = lastConnection?.Invoke(p.Id)?.Rung,
                currentRungAtUtc = lastConnection?.Invoke(p.Id)?.AtUtc,
                // FR-134 / item (16): this pairing's Terms
                // acknowledgment, judged against the CURRENT
                // served Terms — termsPending is the card's
                // "Terms update pending" truth (never acked, or
                // acked an older text before an update).
                termsAckVersion = p.TermsAckVersion,
                termsAckUtc = p.TermsAckUtc,
                termsCurrentVersion = terms?.Version,
                termsPending = terms is not null && !p.HasCurrentTermsAck(terms.Sha256),
            }).ToArray(),
            gates = gatedClasses.OrderBy(g => g, StringComparer.Ordinal).Select(g => new
            {
                id = g,
                approved = approvedGates.Contains(g),
            }).ToArray(),
            audit = auditTail.Select(e => new
            {
                atUtc = e.AtUtc,
                kind = e.Kind,
                agent = e.AgentName,
                tool = e.Tool,
                operation = e.Operation,
                outcome = e.Outcome,
                durationMs = e.DurationMs,
            }).ToArray(),
            roster = (roster ?? Array.Empty<RosterScopeFact>()).Select(s => new
            {
                id = s.Id,
                kind = s.Kind,
                name = s.Name,
                transportCeiling = s.TransportCeiling.ToArray(),
                companyAdmins = s.CompanyAdminIds.ToArray(),
                users = s.Users.Select(u => new
                {
                    id = u.Id, name = u.DisplayName, kind = u.Kind,
                    pairedBy = u.PairedByUserId, suspended = u.Suspended,
                }).ToArray(),
                userGroups = s.UserGroups.Select(g => new
                {
                    id = g.Id, name = g.Name,
                    members = g.Members.ToArray(), admins = g.Admins.ToArray(),
                }).ToArray(),
                deviceGroups = s.DeviceGroups.Select(g => new
                {
                    id = g.Id, name = g.Name,
                    transportSet = g.TransportSet.ToArray(),
                    deviceIds = g.DeviceIds.ToArray(),
                    devices = g.Devices.Select(d => ShapeDevice(d)).ToArray(),
                }).ToArray(),
                grants = s.Grants.Select(g => new
                {
                    userGroupId = g.UserGroupId, deviceGroupId = g.DeviceGroupId,
                    rights = g.Rights.ToArray(),
                }).ToArray(),
            }).ToArray(),
            humanSessions = (humanSessions ?? Array.Empty<HumanSessionFact>()).Select(h => new
            {
                id = h.Id, scopeId = h.ScopeId, hostDeviceId = h.HostDeviceId,
                initiatorId = h.InitiatorUserId, initiator = h.InitiatorName,
                kind = h.Kind, state = h.State, startedUtc = h.StartedUtc,
                seconds = h.Seconds, recording = h.Recording, isRecording = h.IsRecording,
                acceptedBy = h.AcceptedByUserId, acceptOrigin = h.AcceptOrigin,
                floorHolderId = h.FloorHolderUserId, floorHolder = h.FloorHolderName,
                blanked = h.Blanked, inputBlocked = h.InputBlocked, watermarked = h.Watermarked,
                liveCallKind = h.LiveCallKind, liveCallState = h.LiveCallState,
                // U5: file bytes moved in this session + target devices.
                bytesIn = h.BytesIn, bytesOut = h.BytesOut,
                destinations = (h.Destinations ?? Array.Empty<string>()).ToArray(),
                participants = h.Participants.Select(p => new
                {
                    userId = p.UserId, name = p.Name, role = p.Role, floor = p.Floor,
                    transport = p.Transport,
                }).ToArray(),
                terminalOpen = h.TerminalOpen,
                events = h.RecentEvents.Select(e => new
                {
                    atUtc = e.Utc, kind = e.Kind, actor = e.ActorUserId, detail = e.Detail,
                }).ToArray(),
            }).ToArray(),
            // U5: every pairing's flows, side by side — owner-only
            // surface. Gaps ride along: audited activity the flow
            // records cannot account for is named, never hidden.
            dataFlows = dataFlows is null ? null : new
            {
                agents = dataFlows.Agents.Select(a => new
                {
                    pairingId = a.PairingId, agentName = a.AgentName, sessions = a.SessionCount,
                    bytesIn = a.BytesIn, bytesOut = a.BytesOut, byClass = a.ByClass,
                    tools = a.Tools, destinations = a.Destinations,
                }).ToArray(),
                humanFlows = dataFlows.HumanFlows.Select(h => new
                {
                    sessionId = h.SessionId, bytesIn = h.BytesIn, bytesOut = h.BytesOut,
                    destinations = h.Destinations,
                }).ToArray(),
                gaps = dataFlows.Gaps,
            },
            // W8: every live event watch, complete — pairing +
            // kinds + expiry, for the presence page's rendering
            // (EventWatchLines). Owner's surface only.
            eventWatches = eventWatches is null ? null : eventWatches.Select(w => new
            {
                pairingId = w.PairingId,
                kinds = w.Kinds.OrderBy(k => k, StringComparer.Ordinal).ToArray(),
                expiresUtc = w.ExpiresUtc,
            }).ToArray(),
            endpoint = endpoint is null ? null : new
            {
                device = ShapeDevice(endpoint.Device),
                allowedOperators = endpoint.AllowedOperators.Select(o => new
                {
                    name = o.EnrollerName, deviceId = o.EnrollerDeviceId,
                    scope = o.Scope, group = o.GroupName, enrolledUtc = o.EnrolledUtc,
                }).ToArray(),
                receiptCount = endpoint.ReceiptCount,
            },
            transport = transport is null ? null : new
            {
                lanListening = transport.LanListening,
                lanPort = transport.LanPort,
                lanAccepted = transport.LanAccepted,
                lanRefused = transport.LanRefused,
                hubListening = transport.HubListening,
                hubPort = transport.HubPort,
                hubAccepted = transport.HubAccepted,
                hubRefused = transport.HubRefused,
                meshSetupStage = transport.MeshSetupStage,
                meshSetupDetail = transport.MeshSetupDetail,
                events = transport.Events.Select(e => new
                {
                    kind = e.Kind, rung = e.Rung, detail = e.Detail,
                    fromSessionId = e.FromSessionId, toSessionId = e.ToSessionId,
                }).ToArray(),
            },
            enterprise = enterprise is null ? null : new
            {
                policyState = enterprise.PolicyState,
                policyLoaded = enterprise.PolicyLoaded,
                chainOk = enterprise.ChainOk,
                chainSummary = enterprise.ChainSummary,
                alertCount = enterprise.AlertCount,
                breakGlassRotationRequired = enterprise.BreakGlassRotationRequired,
                realIdpBoundary = enterprise.RealIdpBoundary,
                pointerSigningPostureAudit = enterprise.PointerSigningPostureAuditState,
                updateSigningPostureAudit = enterprise.UpdateSigningPostureAuditState,
                anchorMarker = enterprise.AnchorMarkerState,
            },
            blockG = blockG is null ? null : new
            {
                wakeTargets = blockG.WakeTargets,
                standaloneJobsLive = blockG.StandaloneJobsLive,
                totpEnrollmentsActive = blockG.TotpEnrollmentsActive,
                passkeysRegistered = blockG.PasskeysRegistered,
                sessionTunnelsOpen = blockG.SessionTunnelsOpen,
                featureStates = blockG.FeatureStates,
            },
            mesh = mesh is null ? null : new
            {
                state = mesh.State,
                phone = mesh.PhoneName,
                phoneWatching = mesh.PhoneWatching,
            },
            chatThreads = chatThreads is null ? null : chatThreads.Select(t => new
            {
                pairingId = t.PairingId,
                unreadMessages = t.UnreadMessages,
                pendingOrders = t.PendingOrders,
                lastActivityMs = t.LastActivityMs,
                pendingOrderList = t.PendingOrderList.Select(o => new
                {
                    id = o.Id, tool = o.Tool, gateClass = o.GateClass,
                    argumentsJson = o.ArgumentsJson, title = o.Title,
                    targetDevice = o.TargetDevice, createdAtMs = o.CreatedAtMs,
                }).ToArray(),
            }).ToArray(),
            recovery = recovery is null ? null : new
            {
                deviceId = recovery.DeviceId,
                lastExportUtc = recovery.LastExportUtc,
                lastRestoreUtc = recovery.LastRestoreUtc,
                lastRestoredDeviceId = recovery.LastRestoredDeviceId,
                lastRestorePairings = recovery.LastRestorePairings,
                lastRestoreRosterEntries = recovery.LastRestoreRosterEntries,
            },
        };
        return JsonSerializer.Serialize(doc);
    }

    private static object ShapeDevice(RosterDeviceFact d) => new
    {
        deviceId = d.DeviceId, name = d.DisplayName, groupId = d.GroupId,
        groupName = d.GroupName, scope = d.Scope, enrolledUtc = d.EnrolledUtc,
        revoked = d.Revoked, transportMode = d.TransportMode,
        sas = d.Sas, sasConfirmed = d.SasConfirmed,
        sasState = d.SasConfirmed ? "sas_confirmed" : "sas_unconfirmed",
    };

    /// <summary>Shape the D14 blast list for the window's pre-fire
    /// display. Ids and counts only — the window shows exactly what
    /// firing will touch, and nothing else exists in this shape.</summary>
    public static string ShapeBlastJson(Acp.Shared.Roster.OffboardingBlast blast)
    {
        return JsonSerializer.Serialize(new
        {
            scopeId = blast.ScopeId,
            userId = blast.UserId,
            userGroupSeats = blast.UserGroupSeatIds.ToArray(),
            userGroupAdminSeats = blast.UserGroupAdminSeatIds.ToArray(),
            companyAdminSeat = blast.CompanyAdminSeat,
            grants = blast.Grants.Select(g => new
            {
                userGroupId = g.UserGroupId, deviceGroupId = g.DeviceGroupId,
                rights = g.Rights.ToArray(),
            }).ToArray(),
            mintedEnrollmentDeviceIds = blast.MintedEnrollmentDeviceIds.ToArray(),
            ownedAiUserIds = blast.OwnedAiUserIds.ToArray(),
            requiresLiveSessionTermination = blast.RequiresLiveSessionTermination,
            liveSessionRequirement = blast.LiveSessionRequirement,
        });
    }
}
