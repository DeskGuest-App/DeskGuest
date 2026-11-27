using System.Security.Cryptography;
using DeskGuest.Shared.Hub;

namespace DeskGuest.Tests;

/// <summary>FR-133 — the hub binary pin: HubLifecycle must refuse
/// a binary whose bytes differ from HubPins.WindowsBinarySha256,
/// and the binary actually staged in hub-component/ must match
/// the pin byte-for-byte (checked whenever the component folder
/// is present beside the source tree).</summary>
public class HubBinaryPinTests
{
    [Fact]
    public void Pin_IsAFullSha256()
    {
        Assert.Equal(64, HubPins.WindowsBinarySha256.Length);
        Assert.True(HubPins.WindowsBinarySha256.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'));
    }

    private sealed class FakeHubProcess : IHubProcess
    {
        public bool IsRunning { get; private set; }
        public void Start(string binaryPath, string configPath, string workingDir) => IsRunning = true;
        public void Stop() => IsRunning = false;
        public bool HealthOk(string healthUrl) => IsRunning;
    }

    [Fact]
    public void Lifecycle_RefusesABinaryThatDiffersFromThePin()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "deskguest-hubpin-" + Guid.NewGuid().ToString("N")));
        try
        {
            var options = new HubOptions
            {
                ComponentHome = dir.FullName,
                ServerUrl = "https://hub.example.test:8085",
                BinarySha256 = HubPins.WindowsBinarySha256,
            };
            // BinaryPath is platform-shaped (headscale.exe on
            // Windows, headscale elsewhere) — write the wrong
            // bytes at the lifecycle's own path.
            File.WriteAllBytes(options.BinaryPath, new byte[] { 1, 2, 3 });
            var lifecycle = new HubLifecycle(options, new FakeHubProcess(), hubRungSelected: true);
            var refusal = lifecycle.VerifyBinary();
            Assert.NotNull(refusal);
            Assert.Contains("hash mismatch", refusal);
            Assert.False(lifecycle.BinaryVerified);
        }
        finally { try { dir.Delete(recursive: true); } catch { } }
    }

    [Fact]
    public void StagedComponentBinary_MatchesThePin_WhenPresent()
    {
        // The component folder lives beside the source tree
        // (windows-agent/hub-component), five levels up from the
        // test bin dir. Where a tree carries no component folder
        // (a partial checkout), the pin-vs-lifecycle behaviour
        // above still binds; where it is present, its bytes MUST
        // equal the pin — that equality is the packaging claim.
        var candidate = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "hub-component", "headscale.exe"));
        if (!File.Exists(candidate)) return;
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(candidate))).ToLowerInvariant();
        Assert.Equal(HubPins.WindowsBinarySha256, actual);
    }
}
