using System.Text.Json;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Security;
using Xunit;

namespace DeskGuest.Tests;

/// <summary>M4 (2026-11-17): the companion window renders ONLY the
/// host-state snapshot, so its shaping is pinned here: pairings carry
/// names/scopes/states and never a token; gate approval maps from the
/// approved set; session facts and the audit tail pass through
/// verbatim.</summary>
public class HostStateTests
{
    private static Pairing SamplePairing() => new(
        Id: "p1",
        AgentName: "Muse",
        Scopes: new HashSet<string> { Scopes.Drive, Scopes.Observe, Scopes.Shell, Scopes.Admin },
        CreatedUtc: DateTimeOffset.Parse("2026-11-16T10:00:00Z"),
        ExpiresUtc: null,
        SessionTimeBox: null,
        Revoked: false);

    private static string Build() => HostStateSnapshot.Build(
        coreVersion: "1.2.3.4",
        machineName: "HOST-LAPTOP",
        port: 8741,
        runningLanes: new[] { "loopback", "tailscale" },
        agentConnected: true,
        desktopUnlocked: true,
        userStopInForce: false,
        session: new HostStateSnapshot.SessionFacts(true, "Muse", 139, 18, "Exporting a table"),
        pairings: new[] { SamplePairing() },
        gatedClasses: new[] { "payments", "deletions" },
        approvedGates: new HashSet<string> { "deletions" },
        auditTail: new[]
        {
            new AuditEntry(DateTimeOffset.Parse("2026-11-17T20:00:00Z"), "tool_call", "p1", "Muse",
                "shell_exec", null, null, "executed", "SYSTEM", 84),
        });

    [Fact]
    public void Snapshot_carries_facts_and_no_secrets()
    {
        var json = Build();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("HOST-LAPTOP", root.GetProperty("machineName").GetString());
        Assert.Equal(8741, root.GetProperty("port").GetInt32());
        Assert.True(root.GetProperty("agentConnected").GetBoolean());

        var session = root.GetProperty("session");
        Assert.True(session.GetProperty("active").GetBoolean());
        Assert.Equal("Muse", session.GetProperty("agent").GetString());
        Assert.Equal(139, session.GetProperty("seconds").GetInt64());
        Assert.Equal(18, session.GetProperty("actions").GetInt32());

        var pairing = root.GetProperty("pairings")[0];
        Assert.Equal("Muse", pairing.GetProperty("name").GetString());
        Assert.False(pairing.GetProperty("revoked").GetBoolean());
        Assert.Equal(4, pairing.GetProperty("scopes").GetArrayLength());
        // No token material anywhere in the document.
        Assert.DoesNotContain("token", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Bearer", json);
    }

    [Fact]
    public void Snapshot_maps_gate_approvals_from_the_approved_set()
    {
        using var doc = JsonDocument.Parse(Build());
        var gates = doc.RootElement.GetProperty("gates");
        var byId = gates.EnumerateArray().ToDictionary(
            g => g.GetProperty("id").GetString()!, g => g.GetProperty("approved").GetBoolean());
        Assert.True(byId["deletions"]);
        Assert.False(byId["payments"]);
    }

    [Fact]
    public void Snapshot_audit_tail_is_shaped_for_the_timeline()
    {
        using var doc = JsonDocument.Parse(Build());
        var entry = doc.RootElement.GetProperty("audit")[0];
        Assert.Equal("shell_exec", entry.GetProperty("tool").GetString());
        Assert.Equal("executed", entry.GetProperty("outcome").GetString());
        Assert.Equal(84, entry.GetProperty("durationMs").GetInt64());
    }
}
