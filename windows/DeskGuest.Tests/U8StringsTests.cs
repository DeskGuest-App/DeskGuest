using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace DeskGuest.Tests;

/// <summary>U8 gate — consent / presence / STOP string externalisation
/// (Windows). Proves from the tree itself:
///  1. Strings.resx carries every key in the Strings.cs built-in
///     defaults with EXACTLY the same value (wording is law —
///     externalised, never reworded).
///  2. Lint leg: the named consent surfaces (MainWindow session card,
///     Presence, TrayPopup, PortableHelper) contain no hardcoded
///     consent literals and read through Strings.Get/Format.
///  3. Every default value is non-blank — with the Resolve fallback in
///     Strings.cs, a missing/blank resource can never blank the STOP
///     or presence surface (the runtime fallback itself is proven by
///     the U8 reflection harness; vstest is blocked in this sandbox).
/// </summary>
public class U8StringsTests
{
    private static string SessionAgentDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "DeskGuest.SessionAgent");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("DeskGuest.SessionAgent source dir not found above " + AppContext.BaseDirectory);
    }

    private static Dictionary<string, string> ResxValues(string dir)
    {
        var doc = XDocument.Load(Path.Combine(dir, "Strings.resx"));
        return doc.Root!.Elements("data")
            .ToDictionary(d => d.Attribute("name")!.Value, d => d.Element("value")!.Value);
    }

    private static Dictionary<string, string> DefaultsValues(string dir)
    {
        var cs = File.ReadAllText(Path.Combine(dir, "Strings.cs"));
        var map = new Dictionary<string, string>();
        foreach (Match m in Regex.Matches(cs, "\\[\"(\\w+)\"\\] = \"((?:[^\"\\\\]|\\\\.)*)\""))
            map[m.Groups[1].Value] = Regex.Unescape(m.Groups[2].Value);
        return map;
    }

    [Fact]
    public void Resx_matches_builtin_defaults_verbatim()
    {
        var dir = SessionAgentDir();
        var resx = ResxValues(dir);
        var defaults = DefaultsValues(dir);
        Assert.NotEmpty(defaults);
        Assert.Equal(defaults.Keys.OrderBy(k => k), resx.Keys.OrderBy(k => k));
        foreach (var (key, value) in defaults)
        {
            Assert.Equal(value, resx[key]);
            Assert.False(string.IsNullOrWhiteSpace(value), key);
        }
    }

    [Fact]
    public void Consent_surfaces_have_no_hardcoded_literals()
    {
        var dir = SessionAgentDir();
        string[] forbidden =
        {
            "\"STOP\"", "\"STOP Session\"", "\"STOP is in force\"", "\"STOP IS IN FORCE\"",
            "\"CLEAR STOP\"", "\"DISMISS\"", "\"No active session\"",
            "is controlling your PC", "is controlling this PC",
            "STOP — end any help session now",
        };
        foreach (var file in new[] { "MainWindow.xaml.cs", "Presence.cs", "TrayPopup.xaml.cs", "TrayPopup.xaml", "PortableHelper.cs" })
        {
            var code = File.ReadAllText(Path.Combine(dir, file));
            foreach (var bad in forbidden)
                Assert.False(code.Contains(bad), $"{file} still hardcodes {bad}");
        }
        // W74: Presence.cs's STOP door-key is StopEsc since W72
        // (the pill's STOP (ESC) label, Presence.cs pill template +
        // self-test) — the pin names the current key; the law it
        // guards (STOP copy flows through Strings.Get, never a
        // literal) is unchanged.
        Assert.Contains("Strings.Get(\"StopEsc\")", File.ReadAllText(Path.Combine(dir, "Presence.cs")));
        Assert.Contains("Strings.Get(\"Stop\")", File.ReadAllText(Path.Combine(dir, "MainWindow.xaml.cs")));
        Assert.Contains("Strings.Get(\"PortableStop\")", File.ReadAllText(Path.Combine(dir, "PortableHelper.cs")));
        Assert.Contains("Strings.Get(\"StopSession\")", File.ReadAllText(Path.Combine(dir, "TrayPopup.xaml.cs")));
    }
}
