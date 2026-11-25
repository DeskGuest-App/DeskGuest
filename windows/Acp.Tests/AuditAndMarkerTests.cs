using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Heartbeat;

namespace Acp.Tests;

public class AuditAndMarkerTests
{
    [Fact]
    public void RedactJson_MasksCredentialKeys()
    {
        using var doc = JsonDocument.Parse("""{"password":"hunter2","nested":{"api_token":"abc123"},"note":"call me"}""");
        var redacted = Redactor.RedactJson(doc.RootElement).GetRawText();
        Assert.DoesNotContain("hunter2", redacted);
        Assert.DoesNotContain("abc123", redacted);
        Assert.Contains("call me", redacted);
    }

    [Fact]
    public void RedactJson_MasksFreeTextSecretsInCommands()
    {
        // H7 regression: secrets ride inside free-text arguments
        // (shell commands, typed text), not just credential-named keys.
        using var doc = JsonDocument.Parse("""{"command":"curl -H \"Authorization: Bearer <redacted>\" https://x && net use Z: \\\\srv\\share /pass:hunter2"}""");
        var redacted = Redactor.RedactJson(doc.RootElement).GetRawText();
        Assert.DoesNotContain("abc123def456", redacted);
        Assert.DoesNotContain("hunter2", redacted);
    }

    [Fact]
    public void RedactText_MasksBearerTokens()
    {
        var redacted = Redactor.RedactText("Authorization: Bearer <redacted> done");
        Assert.DoesNotContain("supersecrettoken123", redacted);
    }

    [Fact]
    public void AuditLog_AppendAndReadTail_RoundTrips()
    {
        var dir = TestUtil.TempDir();
        var log = TestUtil.AuditLog(dir);
        log.Append(new AuditEntry(DateTimeOffset.UtcNow, "tool_call", "p1", "agent", "endpoint_state", null, "{}", "executed", "SYSTEM", 3));
        log.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "core_started", "SYSTEM", null));
        var tail = log.ReadTail(10);
        Assert.Equal(2, tail.Count);
        Assert.Equal("endpoint_state", tail[0].Tool);
    }

    [Fact]
    public void RunMarker_CleanShutdown_IsCharacterizedClean()
    {
        var path = Path.Combine(TestUtil.TempDir(), "marker.json");
        var state = TestUtil.State();
        var marker = new RunMarker(path);
        marker.Beat(state, "alive");
        marker.MarkCleanShutdown(state);
        var previous = new RunMarker(path).ReadPreviousRun();
        Assert.NotNull(previous);
        Assert.True(previous!.EndedCleanly);
        Assert.Contains("cleanly", previous.Characterization);
    }

    [Fact]
    public void RunMarker_UncleanEnd_IsCharacterizedAsOutage()
    {
        var path = Path.Combine(TestUtil.TempDir(), "marker.json");
        var state = TestUtil.State();
        var marker = new RunMarker(path);
        marker.Beat(state, "last word before the plug was pulled");
        var previous = new RunMarker(path).ReadPreviousRun();
        Assert.NotNull(previous);
        Assert.False(previous!.EndedCleanly);
        Assert.Contains("did NOT end cleanly", previous.Characterization);
    }
}
