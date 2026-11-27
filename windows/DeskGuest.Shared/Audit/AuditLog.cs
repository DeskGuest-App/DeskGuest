using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DeskGuest.Shared.Audit;

/// <summary>Shared audit-detail escaping (bd-shared-sec-1/F12): caller
/// free text is percent-escaped before it is spliced into
/// space-separated key=value audit details, so a value like
/// "x outcome=duplicate" can never mint spoofed fields for anyone
/// parsing the exports. Canonical home is HERE (the Audit lane);
/// EncryptionAuditText delegates to this implementation.</summary>
public static class AuditText
{
    public static string Escape(string? s) => (s ?? "")
        .Replace("%", "%25").Replace(" ", "%20").Replace("=", "%3D")
        .Replace("\r", "%0D").Replace("\n", "%0A").Replace("\t", "%09");
}

/// <summary>
/// Host-side redaction (SPEC §8.3, DESIGN §6.4). Applied BEFORE anything is
/// stored or returned: values under credential-class keys, OTP-shaped
/// values, card numbers, and email local-parts never reach the log.
/// </summary>
public static partial class Redactor
{
    private static readonly string[] SensitiveKeyFragments =
        { "password", "passwd", "otp", "pin", "secret", "token", "credential", "api_key", "apikey", "auth" };

    [GeneratedRegex(@"\b\d{13,19}\b")]
    private static partial Regex CardLike();

    [GeneratedRegex(@"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")]
    private static partial Regex EmailLike();

    [GeneratedRegex(@"\b\d{6}\b")]
    private static partial Regex SixDigit();

    [GeneratedRegex(@"(?i)(bearer|basic)\s+[A-Za-z0-9+/=_\-.]+")]
    private static partial Regex AuthHeaderLike();

    [GeneratedRegex(@"(?i)(password|passwd|pwd|pass|token|secret|api[-_ ]?key)(\s*[:=]\s*|\s+)(\S+)")]
    private static partial Regex KeyValueSecret();

    [GeneratedRegex(@"(?i)(/pass:|/password:|/user:)\S+")]
    private static partial Regex CliSecret();

    // bd-shared-sec-1/F7(4): fragments match on TOKEN boundaries
    // (split on non-alphanumerics and camelCase transitions), never
    // as raw substrings — 'author', 'spinner' and 'shipping' are not
    // credential keys, while 'authToken' and 'api_key' still are.
    private static readonly HashSet<string> SensitiveTokens = new(StringComparer.OrdinalIgnoreCase)
        { "password", "passwd", "otp", "pin", "secret", "token", "credential", "api", "key", "apikey", "auth", "pwd" };

    private static IEnumerable<string> KeyTokens(string key)
    {
        var sb = new StringBuilder();
        foreach (var c in key ?? "")
        {
            if (!char.IsLetterOrDigit(c))
            {
                if (sb.Length > 0) { yield return sb.ToString(); sb.Clear(); }
                continue;
            }
            if (char.IsUpper(c) && sb.Length > 0 && char.IsLower(sb[^1]))
            { yield return sb.ToString(); sb.Clear(); }
            sb.Append(c);
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    public static bool IsSensitiveKey(string key) =>
        KeyTokens(key).Any(t => SensitiveTokens.Contains(t)) ||
        SensitiveKeyFragments.Any(f => string.Equals(key?.Trim(), f, StringComparison.OrdinalIgnoreCase));

    /// <summary>Luhn check (bd-shared-sec-1/F7(3)): a 13–19 digit
    /// run is a CARD only when it passes Luhn — 13-digit epoch
    /// timestamps and other long numbers are not mangled. Same
    /// algorithm as Dlp.PaymentCardClassifier.LuhnValid.</summary>
    public static bool LuhnValid(string digits)
    {
        if (string.IsNullOrEmpty(digits) || digits.Any(c => !char.IsDigit(c))) return false;
        var sum = 0; var dbl = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    public static string RedactText(string text)
    {
        // F7(3): card-shaped runs redact only when Luhn-valid.
        var t = CardLike().Replace(text, m => LuhnValid(m.Value) ? "[redacted:card]" : m.Value);
        // F7(2): a 6-digit OTP redacts wherever it stands in the
        // text, not only when it is the whole string.
        t = SixDigit().Replace(t, "[redacted:otp-like]");
        t = EmailLike().Replace(t, "$1***$2");
        // Free-text secrets (second-inspector H7): a shell command or a
        // typed string can carry a credential in prose form — headers,
        // key=value pairs, CLI switches. Pattern-redact them all; the
        // audit log must never become the place secrets accumulate.
        t = AuthHeaderLike().Replace(t, "$1 [redacted]");
        t = KeyValueSecret().Replace(t, "$1$2[redacted]");
        t = CliSecret().Replace(t, "$1[redacted]");
        return t;
    }

    /// <summary>Deep-redact a JSON argument payload for the audit log.</summary>
    public static JsonElement RedactJson(JsonElement element)
    {
        using var doc = JsonDocument.Parse(RedactNode(element).GetRawText());
        return doc.RootElement.Clone();
    }

    private static JsonElement RedactNode(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var parts = new List<string>();
                foreach (var prop in element.EnumerateObject())
                {
                    var value = IsSensitiveKey(prop.Name)
                        ? "\"[redacted]\""
                        : RedactNode(prop.Value).GetRawText();
                    parts.Add($"{JsonSerializer.Serialize(prop.Name)}:{value}");
                }
                using (var d = JsonDocument.Parse("{" + string.Join(",", parts) + "}"))
                    return d.RootElement.Clone();
            case JsonValueKind.Array:
                var items = element.EnumerateArray().Select(RedactNode).Select(e => e.GetRawText());
                using (var d = JsonDocument.Parse("[" + string.Join(",", items) + "]"))
                    return d.RootElement.Clone();
            case JsonValueKind.String:
                var s = element.GetString() ?? "";
                // OTP-shaped standalone values are redacted wherever they appear.
                var redacted = SixDigit().IsMatch(s) && s.Trim().Length <= 8
                    ? "[redacted:otp-like]"
                    : RedactText(s);
                using (var d = JsonDocument.Parse(JsonSerializer.Serialize(redacted)))
                    return d.RootElement.Clone();
            case JsonValueKind.Number:
                // F7(1): JSON numbers used to fall through unredacted,
                // so {"card":4111111111111111} and {"code":123456}
                // were logged verbatim. A pure-digit number gets the
                // same card (Luhn-gated) / OTP rules as text.
                var raw = element.GetRawText();
                if (raw.All(char.IsDigit))
                {
                    string? numRedacted =
                        raw.Length is >= 13 and <= 19 && LuhnValid(raw) ? "[redacted:card]" :
                        raw.Length == 6 ? "[redacted:otp-like]" : null;
                    if (numRedacted is not null)
                        using (var d = JsonDocument.Parse(JsonSerializer.Serialize(numRedacted)))
                            return d.RootElement.Clone();
                }
                return element;
            default:
                return element;
        }
    }
}

/// <summary>One append-only audit entry (DESIGN §6.4).</summary>
public sealed record AuditEntry(
    DateTimeOffset AtUtc,
    string Kind,               // tool_call | session | supervision | update | unlock | system
    string? PairingId,
    string? AgentName,
    string? Tool,
    string? Operation,
    string? ArgumentsRedacted, // JSON, already redacted
    string Outcome,            // executed | denied:<reason> | gated | error:<class>
    string? ExecutionContext,  // SYSTEM | Owner | Agent
    long? DurationMs);

public interface IAuditLog
{
    void Append(AuditEntry entry);
    IReadOnlyList<AuditEntry> ReadTail(int maxEntries);
}

/// <summary>
/// Append-only JSONL audit log on the host. There is deliberately no
/// update or delete API: agents cannot alter or delete entries
/// (DESIGN §6.4). One writer lock; reads are tail reads for the
/// `audit_log_read` tool and the self-check write test.
///
/// bd-shared-sec-1/F8: "append-only" is now a VERIFIABLE property,
/// not an API shape. Every line is a chained envelope
/// {entry, seq, prevHash, hash} where hash = HMAC-SHA256 (key held
/// in a sidecar `.key` file beside the log) over seq|prevHash|entry.
/// A sidecar `.anchor` file records the current head hash after
/// every append, so truncating the newest entries disagrees with
/// the anchor and VerifyIntegrity says so. The file ROTATES at a
/// size bound: the full file moves to `&lt;path&gt;.rotated-&lt;seq&gt;`
/// and the new file's first entry chains from the rotated head, so
/// the chain is continuous across rotation. ReadTail seeks
/// BACKWARDS from the end of the file in chunks — it no longer
/// reads the whole file under the writer lock. Legacy plain-entry
/// lines (pre-F8 files) still read back; they carry no chain and
/// VerifyIntegrity reports them as legacy, never as verified.
/// </summary>
public sealed class FileAuditLog : IAuditLog
{
    public const long DefaultMaxBytes = 10L * 1024 * 1024;
    private const string Genesis = "GENESIS";

    private sealed record StoredLine(AuditEntry Entry, long Seq, string PrevHash, string Hash);

    private readonly string _path;
    private readonly long _maxBytes;
    private readonly object _gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    private bool _loaded;
    private long _seq;
    private string _head = Genesis;
    private byte[]? _key;

    public FileAuditLog(string path, long maxBytes = DefaultMaxBytes)
    {
        _path = path;
        _maxBytes = maxBytes > 0 ? maxBytes : DefaultMaxBytes;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    }

    public string FilePath => _path;
    private string KeyPath => _path + ".key";
    private string AnchorPath => _path + ".anchor";

    private byte[] Key()
    {
        if (_key is not null) return _key;
        try
        {
            if (File.Exists(KeyPath))
                _key = Convert.FromBase64String(File.ReadAllText(KeyPath).Trim());
        }
        catch { _key = null; }
        if (_key is null || _key.Length < 16)
        {
            _key = RandomNumberGenerator.GetBytes(32);
            File.WriteAllText(KeyPath, Convert.ToBase64String(_key));
        }
        return _key;
    }

    private string ChainHash(long seq, string prevHash, string entryJson)
    {
        using var hmac = new HMACSHA256(Key());
        return Convert.ToHexString(hmac.ComputeHash(
            Encoding.UTF8.GetBytes($"{seq}|{prevHash}|{entryJson}"))).ToLowerInvariant();
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        _seq = 0; _head = Genesis;
        if (!File.Exists(_path)) return;
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            _seq++;
            try
            {
                var stored = JsonSerializer.Deserialize<StoredLine>(line, JsonOpts);
                if (stored is not null && stored.Hash is not null && stored.Entry is not null)
                { _head = stored.Hash; if (stored.Seq > _seq) _seq = stored.Seq; }
            }
            catch (JsonException) { /* legacy or torn line: counted, not chained */ }
        }
    }

    public void Append(AuditEntry entry)
    {
        lock (_gate)
        {
            EnsureLoaded();
            var entryJson = JsonSerializer.Serialize(entry, JsonOpts);
            var seq = _seq + 1;
            var hash = ChainHash(seq, _head, entryJson);
            var line = JsonSerializer.Serialize(new StoredLine(entry, seq, _head, hash), JsonOpts);
            // Rotation: a full file rolls BEFORE this append; the
            // new file's first entry (this one) chains from the
            // rotated file's head via its PrevHash.
            if (File.Exists(_path) && new FileInfo(_path).Length > 0 &&
                new FileInfo(_path).Length + Encoding.UTF8.GetByteCount(line) + 2 > _maxBytes)
            {
                File.Move(_path, _path + $".rotated-{_seq}", overwrite: true);
            }
            File.AppendAllText(_path, line + Environment.NewLine);
            _seq = seq; _head = hash;
            File.WriteAllText(AnchorPath, hash);
        }
    }

    private static AuditEntry? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try
        {
            var stored = JsonSerializer.Deserialize<StoredLine>(line, JsonOpts);
            if (stored is not null && stored.Entry is not null && stored.Hash is not null)
                return stored.Entry;
        }
        catch (JsonException) { }
        try { return JsonSerializer.Deserialize<AuditEntry>(line, JsonOpts); }
        catch (JsonException) { return null; /* a torn final line is evidence, not a crash */ }
    }

    /// <summary>Read the last lines by seeking backwards from the
    /// end of the file in 8 KB chunks — cost is proportional to the
    /// tail requested, not to the size of the log (F8).</summary>
    private List<string> ReadTailLines(int maxEntries)
    {
        var result = new List<string>();
        if (!File.Exists(_path) || maxEntries <= 0) return result;
        using var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new List<byte>();
        long pos = fs.Length;
        var newlines = 0;
        var chunk = new byte[8192];
        while (pos > 0 && newlines <= maxEntries)
        {
            var toRead = (int)Math.Min(chunk.Length, pos);
            pos -= toRead;
            fs.Seek(pos, SeekOrigin.Begin);
            var read = fs.Read(chunk, 0, toRead);
            for (var i = 0; i < read; i++) if (chunk[i] == (byte)'\n') newlines++;
            buffer.InsertRange(0, chunk.Take(read));
            if (newlines > maxEntries) break;
        }
        var text = Encoding.UTF8.GetString(buffer.ToArray());
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimEnd('\r')).ToList();
        return lines.TakeLast(maxEntries).ToList();
    }

    public IReadOnlyList<AuditEntry> ReadTail(int maxEntries)
    {
        lock (_gate)
        {
            var entries = new List<AuditEntry>();
            foreach (var line in ReadTailLines(maxEntries))
                if (ParseLine(line) is { } e) entries.Add(e);
            return entries;
        }
    }

    /// <summary>Recompute the whole current file's chain: every
    /// envelope's HMAC, every prev-hash link, and the head against
    /// the `.anchor` sidecar (a truncated tail disagrees with the
    /// anchor). Legacy plain lines make the verdict "legacy", not
    /// "verified".</summary>
    public (bool Ok, string Summary) VerifyIntegrity()
    {
        lock (_gate)
        {
            if (!File.Exists(_path)) return (true, "no audit file yet — nothing to verify");
            var prev = Genesis; long expectedSeq = 1; var legacy = 0; var chained = 0;
            foreach (var line in File.ReadLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                StoredLine? stored = null;
                try { stored = JsonSerializer.Deserialize<StoredLine>(line, JsonOpts); }
                catch (JsonException) { }
                if (stored is null || stored.Entry is null || stored.Hash is null)
                { legacy++; expectedSeq++; continue; }
                var entryJson = JsonSerializer.Serialize(stored.Entry, JsonOpts);
                if (!string.Equals(stored.Hash, ChainHash(stored.Seq, stored.PrevHash, entryJson), StringComparison.Ordinal))
                    return (false, $"BROKEN at seq {stored.Seq}: entry hash mismatch (content altered)");
                if (chained > 0 && stored.PrevHash != prev)
                    return (false, $"BROKEN at seq {stored.Seq}: prev-hash link mismatch");
                if (chained == 0 && stored.PrevHash != Genesis && stored.Seq != 1)
                    prev = stored.PrevHash; // rotated file: first entry chains from the rotated head
                prev = stored.Hash; chained++; expectedSeq = stored.Seq + 1;
            }
            if (chained == 0)
            {
                // bd-shared-sec-1/F8 residual (W3 destruction):
                // an anchor sidecar with NO chained entries means
                // a chained file was truncated to empty (or
                // replaced) -- that is BROKEN, not "legacy".
                if (File.Exists(AnchorPath))
                    return (false, "BROKEN: an anchor sidecar exists but the file holds no chained entries — the chained log was truncated to empty or replaced");
                return (true, $"legacy file: {legacy} unchained entr(ies) — readable, not chain-verified (pre-F8 format)");
            }
            if (File.Exists(AnchorPath))
            {
                var anchor = File.ReadAllText(AnchorPath).Trim();
                if (!string.Equals(anchor, prev, StringComparison.Ordinal))
                    return (false, $"BROKEN: file head does not match the anchor sidecar — the newest entries were truncated or the file was replaced (head {prev}, anchor {anchor})");
            }
            return (true, $"OK: {chained} chained entr(ies) verified against the keyed chain + anchor" +
                (legacy > 0 ? $"; {legacy} legacy line(s) predate chaining" : ""));
        }
    }

    /// <summary>Write-test used by the self-check: append a probe entry and read it back.</summary>
    public bool WriteTest()
    {
        var probe = new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "self_check_probe", null, null);
        Append(probe);
        return ReadTail(1).Any(e => e.Outcome == "self_check_probe");
    }
}
