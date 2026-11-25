using System.Globalization;
using System.Resources;

namespace Acp.SessionAgent;

/// <summary>U8: the one door the consent / presence / STOP surfaces
/// use to read their strings. Values live in Strings.resx (default
/// en-US) so the consent surface can be localised. Wording is law:
/// the resx values and the built-in defaults below are the exact
/// English strings the surfaces shipped with — externalised,
/// never reworded.
///
/// Fallback (destruction leg): a missing or blank resource value
/// resolves to the built-in default in <see cref="Defaults"/>, so a
/// resource failure can never blank the STOP button or the presence
/// surface. An unknown key resolves to itself, never to "".</summary>
public static class Strings
{
    // The embedded Strings.resources, read directly (not via
    // ResourceManager) so the lookup never depends on assembly
    // attribute grovelling; any failure leaves the table empty and
    // every key falls back to its built-in default below.
    private static readonly Lazy<IReadOnlyDictionary<string, string>> ResourceTable =
        new(LoadResourceTable);

    public static readonly IReadOnlyDictionary<string, string> Defaults =
        new Dictionary<string, string>
        {
            ["Stop"] = "STOP",
            ["StopEsc"] = "STOP (ESC)",
            ["StopSession"] = "STOP Session",
            ["StopIsInForce"] = "STOP is in force",
            ["StopInForceBanner"] = "STOP IS IN FORCE",
            ["StopInForceBody"] = "Every agent is blocked until you clear STOP. The session that was running has ended.",
            ["ClearStop"] = "CLEAR STOP",
            ["ClearStopAllowAgents"] = "CLEAR STOP — allow agents again",
            ["Dismiss"] = "DISMISS",
            ["ClearingStop"] = "Clearing STOP…",
            ["ActiveSessionBanner"] = "ACTIVE AI SESSION",
            ["SessionBanner"] = "SESSION",
            ["NoActiveSession"] = "No active session",
            ["NoSessionBody"] = "Your AI can only control this PC during a visible session — the glow, the presence box, and the ghost cursor are always on while it works, and STOP is always within reach.",
            ["ControllingYourPcFormat"] = "{0} is controlling your PC",
            ["ControllingThisPcFormat"] = "{0} is controlling this PC",
            ["BlockedNameFormat"] = "{0} is blocked",
            ["PresenceBlockedFormat"] = "{0} is blocked — STOP is in force",
            ["PresenceBlockedHint"] = "Press CLEAR STOP to let the agent work again.",
            ["PresenceIntentFallback"] = "The presence box on your desktop shows what the agent is doing.",
            ["CurrentIntentFormat"] = "Current intent: {0}",
            ["StopHotkeyHintFormat"] = "Keyboard STOP: {0} — always on. The box, this window, and the tray always work too.",
            ["StopHotkeyHint"] = "Keyboard STOP is not assigned yet — the box, this window, and the tray always work.",
            ["StopTrayHint"] = "or use the tray STOP",
            ["ActionSingular"] = "1 action",
            ["ActionsFormat"] = "{0} actions",
            ["MeshBlockedStop"] = "Blocked — STOP in force",
            ["MeshActiveSessionFormat"] = "Active AI session ({0})",
            ["PairingCodeHintFormat"] = "Give this code to your AI to pair. It expires at {0} and works once.",
            ["PairingTrustLine"] = "Give this code only to someone you trust. It works once, for this pairing.",
            ["AccessPageTitleFormat"] = "What {0} may do",
            ["AccessCustomChip"] = "Custom",
            ["AccessFineTune"] = "Fine-tune",
            ["AccessThisChanges"] = "This changes:",
            ["AccessApply"] = "Apply changes",
            ["AccessCancel"] = "Cancel",
            ["AccessNoChanges"] = "No changes waiting.",
            ["AccessAuditNote"] = "Every change is written to the Activity Record.",
            ["AccessElevationConfirm"] = "Turn on admin jobs for this helper",
            ["AccessRevokedLine"] = "This pairing is revoked — it has no access, and access can't be changed.",
            ["AccessNoPairings"] = "No AI helpers are paired yet. Pair one on the Add a Device page and its access controls will appear here.",
            ["AccessGrantAddedFormat"] = "+ {0}",
            ["AccessGrantRemovedFormat"] = "− {0}",
            ["PairingNoCodeYet"] = "No code yet — name your AI above, then create a pairing code.",
            ["PairingExpiresInFormat"] = "Expires in {0} — after that, make a new one.",
            ["PairingExpiredLine"] = "That code has expired — create a new one.",
            ["PairingReachFormat"] = "This PC is reachable over {0}.",
            ["PairingEnterHint"] = "Redeem an enrollment code here and this PC joins that roster. The code works once and expires.",
            ["PortableWindowTitle"] = "ACP Quick Assist — portable helper",
            ["PortableTitle"] = "Quick Assist",
            ["PortableIntro"] = "This portable helper installed nothing on your PC. When you close this window, the session code dies with it and the helper is gone.",
            ["PortableCodeHint"] = "Read this code to the person helping you. It works once, for viewing only, and expires in 10 minutes.",
            ["PortableShowCode"] = "Show my session code",
            ["PortableAskingCode"] = "Asking the Core for a code…",
            ["PortableCodeNotMinted"] = "Not connected to the Core — the code was NOT minted.",
            ["PortableStop"] = "STOP — end any help session now",
            ["PortableStopSent"] = "STOP sent. Any session is ending and agents are blocked.",
            ["PortableStopFailed"] = "STOP could not be sent — the Core is not connected. Close this window to end the helper.",
            ["PortableCodeMinted"] = "Code minted. It expires in 10 minutes and works once, for viewing only.",
            ["PresenceTakeoverHint"] = "Press Ctrl + Alt + Shift + Backspace to take over",
            ["PresenceYoureDriving"] = "Paused — you're driving",
            // FR-120 (W73) — the "Taking back control" settings
            // group + the pill's hand-back control. Zero-knowledge
            // copy: one plain sentence per mode, no jargon.
            ["TakeoverGroupTitle"] = "Taking back control",
            ["TakeoverGroupIntro"] = "While your AI is working, you can take over at any time. Choose what happens when you touch the mouse or the keyboard. STOP always ends the session right away, whatever you choose here.",
            ["TakeoverMouseLabel"] = "Mouse",
            ["TakeoverKeyboardLabel"] = "Keyboard",
            ["TakeoverModeTakeOver"] = "Take over",
            ["TakeoverModeTakeOverSentence"] = "Touch it and you are driving. Your AI stops and watches until you hand control back.",
            ["TakeoverModeShare"] = "Share",
            ["TakeoverModeShareSentence"] = "You can move and point freely while your AI keeps working. Nothing is interrupted.",
            ["TakeoverModeHotkeyOnly"] = "Hotkey only",
            ["TakeoverModeHotkeyOnlySentence"] = "Touching it changes nothing. Press Ctrl + Alt + Shift + Backspace when you want to take over.",
            ["HandBackControl"] = "HAND BACK",
            ["PresenceIdle"] = "Session open — idle",
            ["PresenceWatchdogLine"] = "This app can't reach the host. It can't confirm whether anything is controlling this PC.",
            ["PresenceStopHost"] = "Stop the host",
            ["GateApprove"] = "Approve",
            ["GateDeny"] = "Deny",
            ["GateDenyAndEnd"] = "Deny and end session",
            ["GateDraftNotSent"] = "DRAFT · NOT SENT",
            ["GateAskedFromChat"] = "Asked from Agent chat",
            ["GateNoSessionAllow"] = "There is no allow-for-this-session. Every gated action asks on its own.",
            ["SessionProviderLineFormat"] = "What {0}'s provider does with what it sees is outside this app.",
            ["SessionVendorLine"] = "Nowhere else — DeskGuest sends nothing to anyone.",
            ["SessionNotSeenFormat"] = "Not seen: {0}",
            ["SessionPresenceOnFrames"] = "The presence layer is part of the screens the agent receives — it is never hidden from the agent.",
            ["SessionSoFar"] = "so far",
            ["ChatCapabilityLine"] = "Messaging does not use this access. It applies only while a session runs.",
            ["ChatSentCountFormat"] = "{0} messages sent from chat",
            ["HostThisPcOnly"] = "You're looking at this PC only.",
            ["FloorBoxTitle"] = "Always on — no one can change this",
            ["WizardWaitingForAi"] = "Waiting for your AI",
            ["WizardSasCheckFormat"] = "Is this {0}? Check the words — they must match what your AI shows.",
            ["KeyboardStopUnassigned"] = "No keyboard STOP is assigned yet. The presence box STOP, this window, and the tray always work.",
            ["PresenceDriverNameMissing"] = "A session tried to run without naming its driver",
            ["PresenceDriverNameMissingHint"] = "It was refused. Presence always names the specific agent — a session that cannot name its driver does not run.",
            ["PosturePointerSigningFormat"] = "Pointer signing posture: {0}",
            ["PostureUpdateSigningFormat"] = "Update signing posture: {0}",
            ["PostureAnchorMarkerFormat"] = "Anchor marker: {0}",
            ["PresenceSelfTestPassed"] = "Presence self-test passed — the box, ghost, and glow all drew, with STOP on the box.",
            ["PresenceSelfTestFailedFormat"] = "Presence self-test FAILED: {0}. A session will not be accepted until presence draws.",
            ["EventWatchesTitle"] = "Event watches (live)",
            ["LedgerTitle"] = "Data-flow ledger",
            ["ComfortGlowIntensity"] = "Glow intensity",
            ["ComfortGlowBreath"] = "Let the glow breathe (6.4 s, gentle)",
            // FR-105 (W85) — the Presence Customizer. The pre-directive
            // comfort-only copy is REMOVED (its key is gone from both
            // string homes): appearance is a real setting now, under
            // the floor these keys state.
            ["PresenceTitle"] = "Presence",
            ["PresenceSub"] = "What your screen shows while your AI is in control: the box naming the agent with STOP, the ghost ring, and the edge glow — exactly three elements, on every display.",
            ["PresenceFloorSentence"] = "You can change how it looks in every way — it just can't disappear while someone is here, and STOP is always STOP.",
            ["PresenceModeNormal"] = "Helping on screen",
            ["PresenceModeBackground"] = "Background Work Only",
            ["PresencePreviewTitle"] = "Preview — every state, as it will really look",
            ["PresenceStateAi"] = "AI driving",
            ["PresenceStatePerson"] = "Person driving",
            ["PresenceStateWaiting"] = "Waiting",
            ["PresenceSizeLabel"] = "Size",
            ["PresenceBrightnessLabel"] = "Brightness",
            ["PresenceDetailLabel"] = "Detail level",
            ["PresenceDetailFull"] = "Full pill",
            ["PresenceDetailCompact"] = "Compact pill",
            ["PresenceColorsTitle"] = "State colors",
            ["PresenceColorAi"] = "AI driving",
            ["PresenceColorPerson"] = "Person driving",
            ["PresenceColorWaiting"] = "Waiting",
            ["PresenceColorStop"] = "STOP",
            ["PresencePointerTitle"] = "Pointer style",
            ["PresencePointerNote"] = "Every style carries a ring in the current state's color, so it never looks like your own pointer.",
            ["PresenceSave"] = "Save appearance",
            ["PresenceReset"] = "Back to defaults",
            ["PresenceSaved"] = "Saved — this is how presence looks on this PC now.",
            ["PresenceBgNote"] = "Background Work Only mode itself is not in this version yet. Here you choose how its indicator will look when it arrives — it follows the same rule: it can never disappear while an AI is connected.",
            ["PresenceBgColor"] = "Indicator color",
            ["PresenceBgPreviewFormat"] = "{0} is working in the background",
            ["PresenceStateWordControlling"] = "Controlling",
            ["PresenceStateWordWaiting"] = "Waiting",
            ["PresencePreviewNameFallback"] = "Your helper",
            ["HostNoFleet"] = "This PC is an endpoint: it holds no fleet, no roster, and no operator keys.",
        };

    public static string Get(string key) => Resolve(key, SafeResource(key));

    public static string Format(string key, params object?[] args) =>
        string.Format(CultureInfo.CurrentCulture, Get(key), args);

    /// <summary>The pure fallback rule, proven by the U8 harness:
    /// a present, non-blank resource value wins; a missing or blank
    /// one falls back to the built-in default.</summary>
    internal static string Resolve(string key, string? resourceValue) =>
        !string.IsNullOrWhiteSpace(resourceValue)
            ? resourceValue
            : Defaults.TryGetValue(key, out var d) ? d : key;

    private static string? SafeResource(string key) =>
        ResourceTable.Value.TryGetValue(key, out var v) ? v : null;

    private static IReadOnlyDictionary<string, string> LoadResourceTable()
    {
        var table = new Dictionary<string, string>();
        try
        {
            var asm = typeof(Strings).Assembly;
            using var stream = asm.GetManifestResourceStream("Acp.SessionAgent.Strings.resources");
            if (stream is null) return table;
            using var reader = new ResourceReader(stream);
            var entries = reader.GetEnumerator();
            while (entries.MoveNext())
                if (entries.Key is string k && entries.Value is string v)
                    table[k] = v;
        }
        catch { /* empty table: every key falls back to its default */ }
        return table;
    }
}
