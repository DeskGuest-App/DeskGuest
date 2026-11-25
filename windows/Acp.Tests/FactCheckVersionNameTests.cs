using Acp.Core.Platform;

namespace Acp.Tests;

/// <summary>FR-129 pins: the OS version name endpoint_state
/// reports is derived from the build number, never trusted from
/// the registry ProductName (which still says "Windows 10" on
/// Windows 11 machines). The bench case is the first row: build
/// 26300 reported as "Windows 10 Home" before the fix.</summary>
public class FactCheckVersionNameTests
{
    [Theory]
    [InlineData("Windows 10 Home", 26300, "Windows 11 Home")]       // the bench machine (FR-129)
    [InlineData("Windows 10 Home", 22000, "Windows 11 Home")]       // first Windows 11 build
    [InlineData("Windows 10 Pro", 22631, "Windows 11 Pro")]
    [InlineData("Windows 11 Pro", 26100, "Windows 11 Pro")]         // already right: stable
    [InlineData("Windows 10 Pro", 19045, "Windows 10 Pro")]         // a real Windows 10: stable
    [InlineData("Windows 10 Enterprise", 21999, "Windows 10 Enterprise")] // last pre-11 build
    [InlineData("Windows 10 Education", 10240, "Windows 10 Education")]   // first Windows 10 build
    public void VersionName_DerivesFromBuildNotProductName(string product, int build, string expected) =>
        Assert.Equal(expected, WindowsVersionName.FromProductName(product, build));

    [Theory]
    [InlineData("Windows Server 2022", 20348)]  // no 10/11 token: its own naming stands
    [InlineData("Windows 8.1 Pro", 9600)]       // pre-10 build: ProductName was honest
    [InlineData("Windows 10 Home", 0)]          // build unreadable: never invent a version
    public void VersionName_PassesThroughWhenNoDerivationApplies(string product, int build) =>
        Assert.Equal(product, WindowsVersionName.FromProductName(product, build));

    [Fact]
    public void VersionName_UnknownProductStaysUnknown()
    {
        Assert.Equal("unknown", WindowsVersionName.FromProductName(null, 26300));
        Assert.Equal("unknown", WindowsVersionName.FromProductName("", 26300));
        Assert.Equal("unknown", WindowsVersionName.FromProductName("   ", 26300));
    }
}
