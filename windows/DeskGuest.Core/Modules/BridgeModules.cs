using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>
/// The Claude bridge as a native module (DESIGN §7.3, census rows
/// 81–82). The standalone watcher script is replaced by Core code under
/// the policy engine and the host audit log: packets land in the
/// staging store, are HMAC-validated against the bridge key, execute
/// single-flight through the unmodified `claude` CLI with a scrubbed
/// environment (no ANTHROPIC_API_KEY — the bridge's billing-route
/// guard), and honour STOP before every run.
/// </summary>
public sealed class BridgeHost
{
    private readonly string _queueDir;
    private readonly byte[] _hmacKey;
    private readonly IProcessRunner _runner;
    private readonly Func<bool> _stopInForce;
    private readonly SemaphoreSlim _singleFlight = new(1, 1);

    public BridgeHost(string dataDir, IProcessRunner runner, Func<bool> stopInForce)
    {
        _queueDir = Path.Combine(dataDir, "bridge-queue");
        Directory.CreateDirectory(_queueDir);
        Directory.CreateDirectory(Path.Combine(_queueDir, "done"));
        _runner = runner;
        _stopInForce = stopInForce;
        var keyPath = Path.Combine(dataDir, "bridge.key");
        if (!File.Exists(keyPath))
        {
            File.WriteAllBytes(keyPath, RandomNumberGenerator.GetBytes(32));
            RestrictKeyFile(keyPath);
        }
        _hmacKey = File.ReadAllBytes(keyPath);
    }

    /// <summary>BD-WIN-CORE-1 F3: the bridge key must not sit in the
    /// data dir with inherited ACLs. On Windows, restrict it to
    /// SYSTEM + Administrators + the configured logon user (the same
    /// set the IPC pipe allows); elsewhere, owner-only mode bits.
    /// Best-effort by design — a failure here never widens access,
    /// and the key remains inside the ACL'd data dir.</summary>
    private static void RestrictKeyFile(string keyPath)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new System.Security.AccessControl.FileSecurity();
                var full = System.Security.AccessControl.FileSystemRights.FullControl;
                var allow = System.Security.AccessControl.AccessControlType.Allow;
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null), full, allow));
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null), full, allow));
                var owner = Environment.GetEnvironmentVariable("DESKGUEST_LOGON_USER");
                if (!string.IsNullOrWhiteSpace(owner))
                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        new System.Security.Principal.NTAccount(owner), System.Security.AccessControl.FileSystemRights.Read, allow));
                new FileInfo(keyPath).SetAccessControl(security);
            }
            else
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch { /* best-effort hardening; see summary */ }
    }

    /// <summary>Packet ids become file names (BD-WIN-CORE-1 F3): a
    /// strict charset, so an id can never traverse out of the queue.</summary>
    public static bool IsValidPacketId(string? id) =>
        id is { Length: >= 1 and <= 64 } && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    public string QueueDir => _queueDir;

    public string ComputeHmac(string packetJson)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(packetJson)));
    }

    public bool ValidatePacket(string packetJson, string providedHmac)
    {
        // BD-WIN-CORE-1 F3: malformed hex (odd length, non-hex,
        // wrong length) is a clean refusal, never an exception —
        // and no padding/truncation games: the provided MAC must be
        // exactly the expected length.
        var expected = ComputeHmac(packetJson);
        if (providedHmac is null || providedHmac.Length != expected.Length) return false;
        byte[] providedBytes;
        try { providedBytes = Convert.FromHexString(providedHmac); }
        catch (FormatException) { return false; }
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expected), providedBytes);
    }

    public sealed record BridgePacket(string Id, string Kind, string Payload, DateTimeOffset QueuedUtc);

    public string QueuePacket(BridgePacket packet)
    {
        if (!IsValidPacketId(packet.Id))
            throw new ArgumentException($"bridge packet id '{packet.Id}' is not a safe queue file name ([A-Za-z0-9-], 1-64 chars)", nameof(packet));
        var path = Path.Combine(_queueDir, $"{packet.Id}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(packet));
        return path;
    }

    public IReadOnlyList<BridgePacket> Pending()
    {
        var list = new List<BridgePacket>();
        foreach (var f in Directory.EnumerateFiles(_queueDir, "*.json"))
        {
            try { list.Add(JsonSerializer.Deserialize<BridgePacket>(File.ReadAllText(f))!); }
            catch (JsonException) { /* a torn packet is skipped, never executed */ }
        }
        return list.OrderBy(p => p.QueuedUtc).ToList();
    }

    /// <summary>Execute one packet through the bridge runner. The runner
    /// is the unmodified claude CLI on the laptop; on hosts without it,
    /// the honest answer is unavailable — never a simulated result.</summary>
    public async Task<ToolResult> RunPacketAsync(BridgePacket packet, CancellationToken ct)
    {
        if (_stopInForce()) return ToolResult.Unavailable("STOP is in force; the bridge does not run packets under STOP");
        if (!await _singleFlight.WaitAsync(0, ct))
            return ToolResult.Unavailable("another bridge packet is already running (single-flight)");
        try
        {
            var claudePath = FindClaudeCli();
            if (claudePath is null)
                return ToolResult.Unavailable("the claude CLI is not installed on this host; bridge_run needs it (the owner's one install, Morning List)");
            // BD-WIN-CORE-1 F3: the packet payload IS the CLI's input
            // — it goes on stdin via -p, and the runner scrubs
            // ANTHROPIC_API_KEY from the spawned environment itself
            // (SystemProcessRunner.RunWithStdinAsync). The packet is
            // marked done ONLY after a successful run; a failed run
            // leaves it queued and visible, never silently "done".
            if (!IsValidPacketId(packet.Id))
                return ToolResult.Error("bad_packet_id", $"bridge packet id '{packet.Id}' is not a safe queue file name; refused");
            var result = await _runner.RunWithStdinAsync(claudePath, "-p --output-format json", packet.Payload, TimeSpan.FromMinutes(10), ct);
            if (result.ExitCode != 0)
                return ToolResult.Error("bridge_run_failed", result.StdErr);
            var queuedPath = Path.Combine(_queueDir, $"{packet.Id}.json");
            if (File.Exists(queuedPath))
                File.Move(queuedPath, Path.Combine(_queueDir, "done", $"{packet.Id}.json"), overwrite: true);
            return ToolResult.Success(result.StdOut);
        }
        finally { _singleFlight.Release(); }
    }

    private static string? FindClaudeCli()
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var candidate = Path.Combine(dir, OperatingSystem.IsWindows() ? "claude.exe" : "claude");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}

public sealed class BridgeQueueModule : IToolModule
{
    private readonly BridgeHost _bridge;
    public BridgeQueueModule(BridgeHost bridge) => _bridge = bridge;
    public ToolDescriptor Descriptor { get; } = new(
        "bridge_queue", "Accept/validate/status for Claude-bridge packets in the staging store (HMAC, single-flight, STOP honoured).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["queue","status"]},"packet":{"type":"object"},"hmac":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "status";
        if (action == "status")
        {
            var pending = _bridge.Pending();
            return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { pending = pending.Select(p => new { p.Id, p.Kind, p.QueuedUtc }) }, new JsonSerializerOptions { WriteIndented = true })));
        }
        if (!arguments.TryGetProperty("packet", out var packetEl))
            return Task.FromResult(ToolResult.Error("bad_arguments", "queue requires {packet, hmac}"));
        var packetJson = packetEl.GetRawText();
        var hmac = FileArgs.Str(arguments, "hmac") ?? "";
        if (!_bridge.ValidatePacket(packetJson, hmac))
            return Task.FromResult(ToolResult.Error("hmac_invalid", "packet HMAC does not validate against the bridge key; refused"));
        var packet = JsonSerializer.Deserialize<BridgeHost.BridgePacket>(packetJson);
        if (packet is null) return Task.FromResult(ToolResult.Error("bad_packet", "packet did not deserialize"));
        try { _bridge.QueuePacket(packet); }
        catch (ArgumentException ex) { return Task.FromResult(ToolResult.Error("bad_packet_id", ex.Message)); }
        return Task.FromResult(ToolResult.Success($"packet {packet.Id} queued"));
    }
}

public sealed class BridgeRunModule : IToolModule
{
    private readonly BridgeHost _bridge;
    public BridgeRunModule(BridgeHost bridge) => _bridge = bridge;
    public ToolDescriptor Descriptor { get; } = new(
        "bridge_run", "Execute the oldest validated bridge packet via the unmodified claude CLI under the bridge's rules (env scrubbed, clean directory, structured result).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var pending = _bridge.Pending();
        if (pending.Count == 0) return ToolResult.Success("bridge queue is empty");
        return await _bridge.RunPacketAsync(pending[0], ct);
    }
}
