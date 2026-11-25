namespace Acp.Shared.Ipc;

/// <summary>
/// Core ↔ Session Agent IPC (DESIGN §3.1): named pipe, ACL'd to SYSTEM +
/// the owner's account on Windows. Length-prefixed JSON frames. The Agent
/// holds no credentials and no policy authority: it executes what the
/// Core's policy engine approved.
/// </summary>
public static class IpcKinds
{
    public const string Hello = "hello";               // Agent → Core, on connect (carries a fresh nonce, NO secret)
    public const string HelloAck = "hello_ack";        // Core → Agent: HMAC proof the peer holds the IPC token (mutual auth, 2026-11-15 blocker fix)
    public const string Auth = "auth";                 // Agent → Core: presents the IPC token, only AFTER the Core proved itself via HelloAck
    public const string Heartbeat = "heartbeat";       // Agent → Core, periodic
    public const string SessionState = "session_state"; // Agent → Core, on change
    public const string ToolRequest = "tool_request";  // Core → Agent
    public const string ToolResponse = "tool_response"; // Agent → Core
    public const string Presence = "presence";         // Core → Agent: session presence on/off + narration
    public const string StopAll = "stop_all";          // Core → Agent: STOP in force
    public const string ClipboardPolicy = "clipboard_policy"; // Core → Agent: the resolved U1 clipboard policy (payload {"direction": "...", "sensitiveSkip": bool}) the desktop engine enforces at the clipboard itself, as the second wall behind the Core's choke point. Pushed on agent auth and with every presence push, so a policy change lands without an agent restart. State only — no content, no credential material.
    public const string ReleaseInputs = "release_inputs"; // Core → Agent: release every held key/button NOW (U7 fail-safe). Sent on session end (any reason) and on pairing revocation mid-session. Consent-floor class: the agent executes it unconditionally — it is not a tool, carries no payload, and no policy or setting can suppress it. The agent ALSO releases on its own pipe disconnect, STOP, and inactive-presence triggers, so this kind is the immediate path, never the only one.
    public const string UserStop = "user_stop";        // Agent → Core: the owner pressed STOP on the laptop
    public const string UserStopClear = "user_stop_clear"; // Agent → Core: the owner cleared STOP from the laptop UI (banner CLEAR STOP or host window). Laptop-UI only, like GateApproval: the person at the keyboard is the consent. Without this kind the block had no exit short of a Core restart (M1, 2026-11-17).
    public const string Notify = "notify";             // Core → Agent: show a message to the owner
    public const string GateApproval = "gate_approval"; // Agent → Core: the laptop UI approves a gate class
    public const string VaultSet = "vault_set";     // Agent → Core: the owner typed his logon password in the laptop window (payload {"password": "..."}). Laptop-UI only, like GateApproval: the human at the keyboard is the consent. The Core vaults it immediately and never logs it.
    public const string VaultWipe = "vault_wipe";   // Agent → Core: the owner wiped the vault from the laptop window.
    public const string VaultState = "vault_state"; // Core → Agent: the vault's resulting state, for the laptop window's status line (a state name only — never the credential).
    public const string HostStateRequest = "host_state_request"; // Agent → Core: the companion window asks for the host state snapshot (M4, 2026-11-17). Laptop-UI only, same channel discipline as GateApproval.
    public const string HostState = "host_state";   // Core → Agent: the host state snapshot JSON (pairings, gates, session facts, audit tail) the companion window renders. Facts only — no secrets (pairing tokens are never in it; only names, scopes, states).
    public const string PairingRevoke = "pairing_revoke"; // Agent → Core: the owner revokes a pairing from the companion window (payload {"id": "..."}). Laptop-UI only.
    public const string PairingCreateCode = "pairing_create_code"; // Agent → Core: the owner mints a pairing code from the companion window (payload {"agentName": "...", "preset": "full_control"|"look_only"}). Laptop-UI only — codes are minted on the host, never remotely (C1).
    public const string PairingCode = "pairing_code"; // Core → Agent: the minted code + expiry for the window to display (payload {"code": "...", "expiresUtc": "..."}). The code is shown once, here, to the person at the keyboard.
    public const string PairingAccess = "pairing_access"; // Agent → Core: the owner changes a pairing's grants from the access-control surface (payload {"id": "...", "scopes": [...], "elevationConfirmed": bool}). Laptop-UI only, a consent kind — the person at the keyboard is the consent; adding the admin (elevation) class additionally requires elevationConfirmed, which the window sets only from the preview's own elevation switch. The Core audits every change (old → new sets).
    public const string PairingConnection = "pairing_connection"; // Agent → Core: the owner changes a pairing's connection-path setting from the agent card (payload {"id": "...", "mode": "auto"|"restricted"|"manual", "allowedRungs": [...], "pinnedRung": "..."}). Laptop-UI only, a consent kind — the person at the keyboard is the consent (W97 / S09(b)). The Core validates at the store and audits every change AND refusal (old → new settings).
    // ---- Slice 2/3 live wiring (Block A, 2026-11-19) ------------------
    // Every kind below travels ONLY over this token-authenticated
    // laptop-UI channel, exactly like GateApproval / VaultSet: the
    // person at the keyboard is the consent. There is deliberately no
    // MCP tool, mesh route, file, or HTTP path into any of them.
    public const string RosterAction = "roster_action"; // Agent → Core: a Slice 2 roster act from the host window (payload {"action": "...", ...}). Sub-actions: create_scope, create_user, create_user_group, create_device_group, add_grant, add_company_admin, remove_user (the D14 offboarding fire — the window must preview first, see RosterOffboardPreview).
    public const string RosterOffboardPreview = "roster_offboard_preview"; // Agent → Core: compute the D14 blast list WITHOUT firing (payload {"scopeId": "...", "userId": "..."}).
    public const string RosterOffboardBlast = "roster_offboard_blast"; // Core → Agent: the blast-list JSON for the window to display before any removal fires.
    public const string SessionAction = "session_action"; // Agent → Core: a Slice 3 session act from the host window (payload {"action": "...", ...}). Sub-actions: create, accept, start, pause, resume, end, stop, add_participant, remove_participant, grant_floor, take_floor, set_watch_only, set_recording. "accept" over THIS channel is the endpoint-local UI act (the 2026-11-19 ruling): the Core honors it with SessionAcceptOrigin.EndpointLocal and with no other origin — an explicit "initiating_channel" origin in the payload refuses.
    public const string EnrollmentMint = "enrollment_mint"; // Agent → Core: mint a Slice 1 enrollment code from the host window (payload {"scope": "...", "groupId": "...", "groupName": "...", "transportMode": "...", "allowedTransports": [...], "mintedByUserId": "..."}). Scope/group are bound at mint, as always (D22).
    public const string EnrollmentCodeMsg = "enrollment_code"; // Core → Agent: the minted enrollment code + QR payload for the window to display once (payload {"code": "...", "qr": "...", "expiresUtc": "..."}).
    public const string EnrollmentRedeem = "enrollment_redeem"; // Agent → Core: redeem an enrollment code for THIS device from the host window (payload {"code": "...", "displayName": "...", "rosterScopeId": "...", "mintedByUserId": "..."}). The Core redeems with its own device identity (DeviceId + public key) — proof of the binding is the Slice 1 fingerprint check.
    public const string ActionResult = "action_result"; // Core → Agent: the outcome of a roster/session/enrollment action (payload {"action": "...", "ok": true|false, "detail": "..."}). Facts only — never a code, token, or key.
    // ---- Transport core (Block C part 1, 2026-11-19) -----------------
    // Same laptop-UI-only discipline: starting a session over the
    // transport layer, re-establishing one, opening the LAN listener,
    // and browsing local discovery are operator acts by the person at
    // the keyboard. There is no MCP/mesh/HTTP path into any of them.
    public const string TransportAction = "transport_action"; // Agent → Core: a Block C transport act from the host window (payload {"action": "...", ...}). Sub-actions: start (walk the device's resolved set; address = connect-by-address on the lan rung), reestablish (end + new-start on the next rung), start_lan_listener, stop_lan_listener, browse_discovery, announce_discovery. Set editing itself rides RosterAction (set_group_transports / set_scope_ceiling / update_device_transports).
    public const string DiscoveryResult = "discovery_result"; // Core → Agent: one browse window's classified results (payload {"devices": [{"name": "...", "hash": "...", "state": "...", "knownPeer": bool, "availableToEnroll": bool}]}). Facts only — a discovered device is never controllable from discovery (D20).
    // ---- Hub component (Block C part 2, 2026-11-19) -------------------
    // Same laptop-UI-only discipline: standing the hub up is an operator
    // act by the person at the keyboard; there is no MCP/mesh/HTTP path.
    public const string HubAction = "hub_action"; // Agent → Core: a hub lifecycle act from the host window (payload {"action": "install"|"start"|"stop"|"status"|"decommission", ...}). "start" runs the §8 self-check against the on-disk config+policy first and refuses on any violation.
    public const string HubMintJoin = "hub_mint_join"; // Agent → Core: mint a one-time hub join ticket for a device (payload {"deviceId": "...", "groupId": "..."}). ACP mints the pre-auth key under the hood (D28/D7); the endpoint never sees an account or sign-in (D3).
    public const string HubJoinTicket = "hub_join_ticket"; // Core → Agent: the join ticket for one-time display to the operator at the keyboard (payload {"deviceId": "...", "command": "...", "expiresUtc": "..."}), mirroring PairingCode/EnrollmentCodeMsg — shown once, here, to the person at the keyboard.
    // ---- Block F surfacing (2026-11-20) -------------------------------
    // Same laptop-UI-only discipline as every kind above.
    public const string EnterpriseAction = "enterprise_action"; // Agent → Core: a Block E enterprise act, live-wired (payload {"action": "...", ...}). Sub-actions: policy_status, policy_reload, update_check, audit_export, audit_verify, alerts, sync_event, break_glass_use, idp_begin, idp_complete.
    public const string TerminalAction = "terminal_action"; // Agent → Core: a session-terminal act (payload {"action": "open"|"write"|"close"|"output", ...}). The Core's TerminalService gates every act (floor holder only; AI needs the pairing scope's named `terminal` capability).
    public const string QuickAssistAction = "quick_assist_action"; // Agent → Core: quick-assist session-code acts (payload {"action": "mint"|"redeem"|"close"|"validate", ...}). Mint answers with QuickAssistCode (shown once, here).
    public const string QuickAssistCode = "quick_assist_code"; // Core → Agent: the minted quick-assist session code for one-time display (payload {"code": "...", "expiresUtc": "..."}).
    public const string WebRtcAction = "webrtc_action"; // Agent → Core: manual-WebRTC code-exchange acts (payload {"action": "create_code"|"accept_code", ...}). Signaling + session binding only — the media leg is labeled media_unavailable_t7_unaudited (T7 unaudited, D37).
    public const string AiPackAction = "aipack_action"; // Agent → Core: local AI pack acts (payload {"action": "status"|"licence"|"accept_licence"|"verify"|"download"|"download_status"|"download_cancel", ...}). Downloads run only from the author's official source against pinned hashes, into the product's pack home (<dataDir>/aipack/<packId>); no override exists. "download" starts the pinned download in the background (licence acceptance + the rmm.aipack_download.enabled policy toggle gate it); "download_status" reports its honest state; "download_cancel" cancels it (already-landed verified files stay and are skipped on a restart of the download).
    public const string TorAction = "tor_action"; // Agent → Core: Tor provisioning acts from the host window (payload {"action": "setup"|"status"|"stop", ...}). W19-C wiring: before this kind, TorSetupService.RunSetupAsync had NO production caller — provisioning was built but unreachable. "setup" runs the setup act (policy-gated by rmm.tor_provisioning.enabled; provisions the pinned component if needed, re-verifies the binary, launches the client-only SOCKS listener, and only then writes tor.json); "status" reports the honest state (unconfigured|configuring|ready|failed-with-reason); "stop" stops the ACP-managed client and removes tor.json. Same laptop-UI-only discipline as every kind above; there is no MCP/mesh/HTTP path into any of them.
    // ---- Block H surfacing (2026-11-21) --------------------------------
    public const string BlockGAction = "blockg_action"; // Agent → Core: Block G service acts from the host window's Services page (payload {"action": "wake_list"|"wake_register"|"wake_unregister"|"wake_send"|"transfers_list"|"transfer_cancel"|"tunnels_list"|"tunnel_close"|"factor_status", ...}). The services enforce every authorization rule; this channel is the device-side surface — including the transfer stop the person at the machine always holds.
    // ---- C20 recovery wiring (2026-11-22) ------------------------------
    // Same laptop-UI-only discipline: exporting or restoring a recovery
    // blob is an owner act at the machine (the owner_takeover
    // discipline). There is no MCP tool, mesh route, file, or HTTP path
    // into either act; the agent-facing recovery_blob tool refuses.
    public const string RecoveryAction = "recovery_action"; // Agent → Core: a C20 recovery act from the host window (payload {"action": "export"|"inspect"|"restore_primary"|"restore_contact", ...}). Export names the output path the owner picked in the window's save dialog; restore names the blob path from the window's open dialog plus the credential the owner typed. Refusals answer with ActionResult, loudly.
    public const string RecoveryKeySheet = "recovery_key_sheet"; // Core → Agent: the export's key sheet for ONE-TIME display in the host window (payload {"keySheet": "...", "deviceId": "...", "primaryPath": "...", "contactPaths": [...]}). Owner channel only: the sheet is never in an ActionResult, never in the host-state snapshot, never in the audit log, and never persisted by the Core.
    // ---- W9 per-action gate (design of record §3, live caller) --------
    // gate_approval above is the CLASS-level standing approval from the
    // Guardrails page. These two kinds are the PER-ACTION gate: when a
    // session action requires endpoint approval, the Core raises one
    // request, the Session Agent shows the §3 GateSheet, and the answer
    // returns on the same RequestId. The answer is a consent-class
    // kind (see IpcConsent): while an agent session holds input, only
    // a physical-human provenance answer is honored — an injected
    // "allow" the controlling agent fabricated is refused by the IPC
    // server before it can reach the Core, and the broker in
    // GateRequests.cs binds every answer to the exact pending request
    // (pairing + session + one-shot consumption), so a replayed or
    // cross-session answer is refused even on this channel.
    public const string GateRequest = "gate_request"; // Core → Agent: one per-action gate request (payload = GateRequests.GateRequestPayload). Carries the exact argument bytes the caller submitted (OI-12: the sheet shows those bytes; the executed call uses the same bytes).
    public const string GateAnswer = "gate_answer";   // Agent → Core: the GateSheet's answer (payload {"requestId": "...", "answer": "allow"|"deny"|"deny_and_end"}), RequestId = the gate request's id. Consent-class.
    // ---- W9 Agent chat host surface (Addendum A parity) ---------------
    // The MCP chat tools live on the Core's MCP surface; these kinds
    // are the HOST side of the same thread: the owner reads and sends
    // from the host window. Laptop-UI-only channel discipline as
    // always; bodies travel only on this owner channel and in the
    // thread store — audit keeps metadata, never text.
    public const string ChatSend = "chat_send"; // Agent → Core: the owner sends a chat message from the host window (payload {"pairingId": "...", "body": "..."}). The Core appends it to that pairing's thread and counts it Sent in the data-flow ledger (off-device, [R4]).
    public const string ChatThreadRequest = "chat_thread_request"; // Agent → Core: the host window asks for one pairing's thread (payload {"pairingId": "..."}).
    // ---- FR-120 tunable takeover (W73) --------------------------------
    public const string TakeoverDefaults = "takeover_defaults"; // Core → Agent: the resolved fleet DEFAULT takeover modes (payload {"mouse": "Share", "keyboard": "HotkeyOnly"} — either may be absent). State only, pushed on agent auth and with every presence push (the U1 clipboard-policy pattern). Defaults only: the agent applies them in memory where the device has not chosen; policy never writes presence.json, and a device-local UI choice outranks them.
    public const string TakeoverEvent = "takeover_event"; // Agent → Core: one FR-120 session-record fact (payload {"kind": "takeover_modes"|"takeover_mode_changed"|"takeover_yield"|"takeover_handback"|"takeover_hotkey", "actor": "owner-local"|"in-session"|..., "detail": "..."}). A REPORT, never an act: it carries mode names and arrival paths only — no input content exists in it. The Core appends it to the audit chain (the agent session's record). Deliberately NOT a consent kind and NOT a write path: nothing in this kind can set a mode.
    public const string ChatThread = "chat_thread"; // Core → Agent: the pairing's thread for the host window (payload {"pairingId": "...", "messages": [{"seq": n, "atMs": n, "direction": "owner"|"agent", "body": "..."}], "orders": [...], "queuedForAgent": n, "thisDevice": "..."}). Owner channel only.
    public const string ChatOrderAnswer = "chat_order_answer"; // Agent → Core: the owner's answer on one S13 order card (payload {"pairingId": "...", "orderId": "...", "answer": "allow"|"deny"|"deny_and_end"} — the GateAnswers vocabulary). The card IS the gate for the order's exact bytes; the Core executes only on allow, through the same policy choke point as a wire call.
}

public sealed record IpcMessage(
    string Kind,
    string? RequestId,
    string? Tool,
    string? ArgumentsJson,
    bool? Ok,
    string? Text,
    string? AgentVersion,
    bool? DesktopUnlocked,
    bool? TakeoverActive,
    string? Narration,
    string? ForegroundTitle = null,
    string? ForegroundProcess = null,
    // The acting agent's NAME (the pairing's AgentName) — carried by
    // Presence messages so the banner can name who is controlling
    // the PC. Kept distinct from AgentVersion (the Hello/Auth field,
    // which is a build string): the 2026-11-17 banner bug was the
    // supervisor leaving this unset while the agent read the version
    // slot and fell back to "An agent".
    string? AgentName = null,
    // BD-SHARED-SESSION F1: input provenance for consent-class kinds.
    // "physical_human" = the Session Agent asserts the act came from a
    // physical keyboard/mouse interaction with the laptop UI (not an
    // injected/agent-driven one). Null = unasserted (legacy senders).
    string? InputProvenance = null,
    // BD-SHARED-SESSION F1: the sender's knowledge that an agent
    // (MCP) session currently holds input on this desktop.
    bool? AgentSessionLive = null);

/// <summary>Input-provenance vocabulary for IpcMessage.InputProvenance.</summary>
public static class IpcProvenance
{
    public const string PhysicalHuman = "physical_human";
    public const string AgentInjected = "agent_injected";
    public const string Unknown = "unknown";
}

/// <summary>BD-SHARED-SESSION F1 — the consent-class IPC guard.
/// Consent-class kinds are acts ONLY a person at the keyboard may
/// perform: gate approval, pairing-code minting, the endpoint-local
/// session accept (SessionAction), vault set, and CLEAR STOP. The
/// Session Agent shares the desktop an AI drives through injected
/// input, so a consent-class message is honored ONLY when it
/// carries an explicit physical-human provenance assertion; an
/// agent-injected or unasserted provenance is refused.
///
/// W10 / V2-C4: the pre-fix guard required provenance ONLY while an
/// agent session was live — with no live session, the bare channel
/// was the consent, so a consent act was applied from the IPC
/// message alone (the V2 finding). Provenance is now required
/// ALWAYS: every legitimate sender is a laptop-UI event handler
/// (a human act by construction) and stamps the assertion; a
/// message without it is not a person's act, whatever the session
/// state. The <paramref name="agentSessionLive"/> parameter is
/// retained for call-site compatibility and for the sender's own
/// under-report check (a sender that knows a session is live
/// cannot launder that away — the flag is OR-ed in and recorded),
/// but it no longer decides honoring.
/// RESIDUAL (named, not hidden): provenance is asserted by the
/// Session Agent process; a fully compromised agent process could
/// forge the assertion. The hardware/secure-desktop confirmation
/// that would close that last step is a platform surface, not a
/// shared-contract one — this guard removes the silent confusion of
/// injected clicks with human consent that F1 demonstrated.</summary>
public static class IpcConsent
{
    public static readonly IReadOnlySet<string> ConsentKinds = new HashSet<string>
    {
        IpcKinds.GateApproval, IpcKinds.PairingCreateCode, IpcKinds.SessionAction,
        IpcKinds.UserStopClear, IpcKinds.VaultSet, IpcKinds.PairingAccess, IpcKinds.PairingConnection,
        // W9: a gate ANSWER is a consent act exactly like a gate
        // approval — the person at the keyboard is the consent, and
        // an agent-injected answer during its own session is not.
        IpcKinds.GateAnswer,
    };

    public static bool IsConsentKind(string? kind) => kind is not null && ConsentKinds.Contains(kind);

    /// <param name="agentSessionLive">The CORE's own truth about
    /// whether an agent session currently holds input (never the
    /// sender's claim alone); the message's own AgentSessionLive
    /// flag is OR-ed in so a sender that knows cannot under-report.
    /// Retained for the record (W10 / V2-C4): honoring no longer
    /// depends on it — provenance is required in every state.</param>
    public static bool CanHonor(IpcMessage msg, bool agentSessionLive)
    {
        if (!IsConsentKind(msg.Kind)) return true;
        _ = agentSessionLive || msg.AgentSessionLive == true; // recorded posture; not the gate
        return string.Equals(msg.InputProvenance, IpcProvenance.PhysicalHuman, StringComparison.Ordinal);
    }
}

/// <summary>Mutual authentication for the Core ↔ Agent pipe
/// (2026-11-15 blocker fix). The original handshake authenticated only
/// the Agent: it presented the per-boot token in its Hello, so a
/// squatter pipe server (the pipe name is fixed and first-come) would
/// RECEIVE the token and could impersonate the Core — including
/// receiving vault passwords. Now: the Agent's Hello carries only a
/// fresh nonce; the Core proves itself with
/// HMAC-SHA256(token, "acp-core-hello:" + nonce); only then does the
/// Agent present the token (Auth). A squatter learns nothing reusable:
/// the nonce is single-connection and the HMAC cannot be forged
/// without the token, which never crosses the pipe before proof.</summary>
public static class IpcAuth
{
    public static string NewNonce()
    {
        Span<byte> bytes = stackalloc byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string ComputeHelloAck(string token, string nonce)
    {
        var key = System.Text.Encoding.UTF8.GetBytes(token);
        var data = System.Text.Encoding.UTF8.GetBytes("acp-core-hello:" + nonce);
        return Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(key, data)).ToLowerInvariant();
    }

    public static bool VerifyHelloAck(string token, string nonce, string? ack)
    {
        if (string.IsNullOrWhiteSpace(ack)) return false;
        var expected = ComputeHelloAck(token, nonce);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(expected),
            System.Text.Encoding.UTF8.GetBytes(ack.Trim().ToLowerInvariant()));
    }
}

/// <summary>4-byte little-endian length-prefixed UTF-8 JSON framing.</summary>
public static class IpcFraming
{
    public static async Task WriteAsync(Stream stream, string json, CancellationToken ct)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        var prefix = BitConverter.GetBytes(bytes.Length);
        await stream.WriteAsync(prefix, ct);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>BD-SHARED-SESSION F12: a frame arriving BEFORE the
    /// peer authenticated is capped small — no 64 MB allocation is
    /// ever made on an unauthenticated peer's say-so. The full cap
    /// applies only after Auth.</summary>
    public const int PreAuthMaxFrameBytes = 64 * 1024;
    public const int MaxFrameBytes = 64 * 1024 * 1024;

    public static Task<string?> ReadAsync(Stream stream, CancellationToken ct) =>
        ReadAsync(stream, ct, MaxFrameBytes);

    public static async Task<string?> ReadAsync(Stream stream, CancellationToken ct, int maxFrameBytes)
    {
        var prefix = new byte[4];
        var read = 0;
        while (read < 4)
        {
            var n = await stream.ReadAsync(prefix.AsMemory(read, 4 - read), ct);
            if (n == 0) return null;
            read += n;
        }
        var length = BitConverter.ToInt32(prefix);
        if (length <= 0 || length > Math.Min(maxFrameBytes, MaxFrameBytes)) return null;
        var buffer = new byte[length];
        read = 0;
        while (read < length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, length - read), ct);
            if (n == 0) return null;
            read += n;
        }
        return System.Text.Encoding.UTF8.GetString(buffer);
    }
}
