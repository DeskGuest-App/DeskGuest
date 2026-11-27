using System.Text;

namespace DeskGuest.Shared.Sessions;

/// <summary>
/// W9 — Agent chat store (Addendum A; Android AgentChatStore parity,
/// W8-B semantics). One thread per pairing, keyed by the pairing's
/// unique id (never a display name). The thread is NOT a session:
/// sending a message starts nothing, grants nothing, and shows no
/// presence. Unpairing ENDS the thread: its file is removed with
/// the pairing.
///
/// Persistence mirrors the Android store byte-for-byte in shape:
/// one file per pairing under the chat dir, lines of
/// `atMs|direction|base64(body)` — bodies live ONLY in the thread
/// file the owner reads in the chat surface. Audit keeps message
/// METADATA, never text (see ChatAuditEvent).
///
/// Sync is a monotone cursor: every message carries its 1-based
/// sequence number in the thread; LoadAfter(afterSeq) returns
/// exactly the messages after the cursor plus the next cursor, so
/// a reconnecting agent resumes without loss or duplication.
/// Delivery is PULL-based — no server-initiated push leg for
/// message bodies exists on this architecture — and the tool
/// descriptions say so rather than implying push.
/// </summary>
public sealed class AgentChatStore
{
    public const string DirOwner = "owner";
    public const string DirAgent = "agent";

    /// <summary>Android ChatToolHost.MAX_BODY_CHARS parity.</summary>
    public const int MaxBodyChars = 4000;

    private readonly string _chatDir;
    private readonly object _gate = new();

    public AgentChatStore(string chatDir) => _chatDir = chatDir ?? throw new ArgumentNullException(nameof(chatDir));

    public sealed record Message(long AtMs, string Direction, string Body);
    public sealed record Sequenced(long Seq, Message Message);

    /// <summary>Metadata only — pairing, direction, length, time.
    /// The body never enters an audit/accounting structure.</summary>
    public sealed record ChatAuditEvent(string PairingId, string Direction, int Chars, long AtMs);

    private string ThreadFile(string pairingId)
    {
        var safe = new string((pairingId ?? "").Select(c =>
            char.IsLetterOrDigit(c) || c is '_' or '-' ? c : '_').ToArray());
        return Path.Combine(_chatDir, safe + ".thread");
    }

    public IReadOnlyList<Message> Load(string pairingId)
    {
        lock (_gate)
        {
            var f = ThreadFile(pairingId);
            if (!File.Exists(f)) return Array.Empty<Message>();
            var result = new List<Message>();
            foreach (var line in File.ReadLines(f))
            {
                var parts = line.Split('|', 3);
                if (parts.Length != 3) continue;
                if (!long.TryParse(parts[0], out var at)) continue;
                string body;
                try { body = Encoding.UTF8.GetString(Convert.FromBase64String(parts[2])); }
                catch { continue; }
                result.Add(new Message(at, parts[1], body));
            }
            return result;
        }
    }

    /// <summary>Messages after the caller's cursor, with their
    /// 1-based sequence numbers — the chat_read leg.</summary>
    public IReadOnlyList<Sequenced> LoadAfter(string pairingId, long afterSeq)
    {
        var all = Load(pairingId);
        var result = new List<Sequenced>();
        for (var i = 0; i < all.Count; i++)
            if (i + 1 > afterSeq) result.Add(new Sequenced(i + 1, all[i]));
        return result;
    }

    /// <summary>The cursor a reader passes next time: the thread's
    /// current length (the last sequence number handed out).</summary>
    public long NextCursor(string pairingId) => Load(pairingId).Count;

    /// <summary>Append one message; returns its sequence number and
    /// the metadata-only audit event for the caller to emit. Blank
    /// and over-limit bodies are refused by the CALLERS (the tool /
    /// the host window) before they reach here — the store's own
    /// guard is the same refusal, so no path can persist one.</summary>
    public (long Seq, ChatAuditEvent Audit) Append(string pairingId, string direction, string body, long atMs)
    {
        if (string.IsNullOrWhiteSpace(body)) throw new ArgumentException("chat body is empty", nameof(body));
        if (body.Length > MaxBodyChars) throw new ArgumentException($"chat body exceeds {MaxBodyChars} characters", nameof(body));
        lock (_gate)
        {
            Directory.CreateDirectory(_chatDir);
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(body));
            File.AppendAllText(ThreadFile(pairingId), $"{atMs}|{direction}|{encoded}\n", Encoding.UTF8);
            var seq = Load(pairingId).Count;
            return (seq, new ChatAuditEvent(pairingId, direction, body.Length, atMs));
        }
    }

    /// <summary>Unpairing ends the thread: the file is removed and
    /// both legs refuse/empty for the dead pairing thereafter.</summary>
    public void EndThread(string pairingId)
    {
        lock (_gate)
        {
            var f = ThreadFile(pairingId);
            if (File.Exists(f)) File.Delete(f);
        }
    }

    public bool ThreadExists(string pairingId)
    {
        lock (_gate) return File.Exists(ThreadFile(pairingId));
    }
}
