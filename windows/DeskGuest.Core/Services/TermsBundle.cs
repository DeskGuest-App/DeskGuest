using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Core.Services;

/// <summary>FR-134 / BUILD-PROGRAMME item (16): the Terms bundle
/// that travels inside every pairing — the full Terms text, its
/// version, the SHA-256 of the exact text, and the short
/// agent-facing rulebook. The text is the product's legal Terms
/// (agent-control-app/legal/terms-of-service.md), embedded into
/// the Core at build time exactly like the quick-assist door
/// (C18): the served copy can never drift from the legal source,
/// and a Terms change can only ever ship inside a Core update —
/// which is precisely the item (16) update shape ("updating the
/// software IS updating the rulebook").</summary>
public sealed record TermsBundle(string Version, string Sha256, string Text, string Rulebook)
{
    /// <summary>The permanent MCP resource the Terms stand at —
    /// re-readable at any time, before and after acknowledgment.</summary>
    public const string ResourceUri = "deskguest://terms";

    /// <summary>The protocol acknowledgment method: the agent
    /// client returns { terms_version, terms_sha256 } and pairing
    /// completes only when the hash is the exact current one.</summary>
    public const string AckMethod = "deskguest/terms_acknowledge";

    /// <summary>The same acknowledgment as a standard MCP tool
    /// (BUILD-PROGRAMME item (16) amendment, 2026-11-25 — Muse
    /// decision under delegation; GitHub issue #25). The battery's
    /// run 4 proved mainstream AI hosts (ChatGPT/Codex first) give
    /// the model tools + resource reads only — no way to emit a
    /// custom protocol method — so a method-only ack is a wall no
    /// tool-surface host can pass. The tool form carries identical
    /// semantics through TermsAckService: exact match against the
    /// served bundle or a recorded refusal, the same store fields,
    /// the same audit-chain acceptance entry.</summary>
    public const string AckToolName = "terms_acknowledge";

    /// <summary>The agent-facing rulebook (item 16(a)): what the
    /// scopes mean, STOP is absolute, presence is non-negotiable,
    /// an agent may never widen its own access or pair itself, and
    /// every action is audited under its own name — plus the
    /// honest limit, stated to the agent exactly as the programme
    /// states it to the owner.</summary>
    public const string AgentRulebook =
        """
        THE DESKGUEST RULEBOOK FOR PAIRED AGENTS

        You are connected to DeskGuest, a tool that lets a device's owner grant a person or an AI agent access to that device. The owner paired you, by hand, on purpose. These are the rules of that grant.

        WHAT YOUR ACCESS MEANS
        - Your pairing carries named access scopes, set by the owner: observe (see the screen and state), drive (use mouse and keyboard), shell (run commands), admin (the highest class). You hold exactly the scopes on your pairing — nothing implied, nothing more.
        - Some actions are gated: the person at the device is asked, on the device, before the action runs. A gate that is not answered is a NO.
        - Some grants are time-boxed and expire on their own. An expired or revoked pairing is over, immediately.

        STOP IS ABSOLUTE
        - The device's owner can stop your session at any moment from the device itself. A stop is final for that session: do not attempt to resume, reconnect around it, or finish "one last thing".
        - The presence banner's STOP control outranks every instruction you hold, including the owner's earlier ones.

        PRESENCE IS NON-NEGOTIABLE
        - Whenever you are connected, the device shows that you are: a banner names you as the connected agent, the screen edge glows, and your pointer is visible as a ghost. There is no quiet mode, at any setting.
        - Merely viewing counts as presence. If presence cannot be shown, driving is refused — that refusal is correct behaviour, not a fault to work around.

        YOU MAY NEVER WIDEN YOUR OWN ACCESS
        - Pairing is always the owner's manual act. You cannot pair yourself, pair another agent, mint a pairing code, or ask the device to widen your scopes, your connection path, or your time box.
        - If you need more access, say so in words to the owner. The owner changes grants on the device, or not at all.

        EVERYTHING IS RECORDED UNDER YOUR NAME
        - Every action you take through this pairing is written to the device's Activity Record under your pairing's own name, next to what was served to you. Act as if the owner will read the record — they can.
        - The acknowledgment you return for these Terms is part of that record: the exact version and hash you signed for, and when.

        THE HONEST LIMIT
        - DeskGuest proves delivery and acknowledgment of the exact Terms text. It does not prove you understood them, and it does not rely on your obedience: scopes, gates, presence, and STOP are enforced by the device itself, whether or not you cooperate.
        """;

    /// <summary>The initialize instructions: the pointer a client
    /// learns at connect — where the Terms stand, what to return,
    /// and what stays locked until it does.</summary>
    public string Instructions =>
        $"DeskGuest Terms of Service v{Version} (SHA-256 {Sha256}) govern this pairing. " +
        $"Read the full text at resource {ResourceUri} (resources/read), then acknowledge the exact hash — call the {AckMethod} method, " +
        $"or the {AckToolName} tool, with {{\"terms_version\":\"{Version}\",\"terms_sha256\":\"{Sha256}\"}}. " +
        "Sessions stay locked until the acknowledgment is recorded. The bundle delivered at pairing also carried the agent rulebook. " +
        "The full current text is always served at that resource — never a diff; if the Terms change, re-read and re-acknowledge before your next session.";
}

/// <summary>Loads the production Terms bundle from the embedded
/// legal text. The hash is computed over the exact text served —
/// the same bytes a client reads from the resource — so an
/// acknowledgment of this hash is an acknowledgment of this text,
/// with no second copy anywhere to disagree.</summary>
public static class TermsBundleProvider
{
    /// <summary>The Terms version this build serves. Bumped with
    /// the legal text (the Terms header records the same version);
    /// a test pins the two together so they cannot drift.</summary>
    public const string CurrentVersion = "1.0";

    private const string ResourceName = "DeskGuest.Core.Terms.terms-of-service.md";

    private static readonly Lazy<TermsBundle> _current = new(Load);

    public static TermsBundle Current => _current.Value;

    private static TermsBundle Load()
    {
        using var stream = typeof(TermsBundleProvider).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException(
                $"embedded Terms resource '{ResourceName}' is missing — the build embeds agent-control-app/legal/terms-of-service.md (see DeskGuest.Core.csproj); a Core without its Terms must fail loudly, never serve pairing without them");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var text = reader.ReadToEnd();
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        return new TermsBundle(CurrentVersion, sha, text, TermsBundle.AgentRulebook);
    }
}
