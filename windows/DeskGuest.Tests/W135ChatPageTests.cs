namespace DeskGuest.Tests;

/// <summary>
/// W135 — S13 as a FULL-WINDOW page in the shell (coordinator
/// ruling U-7 on the W131 structural finding: the magnum-opus
/// master is a full-window chat; the thread's embedding in
/// Home's helpers column was the surface's largest diff class).
/// The pins: the shell has a chat page; every entry point (Home
/// agent card, S09(d), the N22 inbox lens) navigates to it; the
/// thread is no longer embedded on Home; the page composes
/// header / capability line / scrolling timeline / pinned
/// composer; the host scroller stands down while chat is
/// current and the page sizes itself to the viewport.
/// </summary>
public class W135ChatPageTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    [Fact]
    public void Shell_HasAChatPage_BuiltByTheChatSurface()
    {
        var shell = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("\"chat\" => BuildChatPage()", shell);
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("private UIElement BuildChatPage()", chat);
        Assert.Contains("private void RenderChatPage()", chat);
    }

    [Fact]
    public void EveryEntryPoint_NavigatesToTheChatPage()
    {
        var inbox = SrcFile("DeskGuest.SessionAgent", "MainWindow.Inbox.cs");
        Assert.Contains("ShowPage(\"chat\")", inbox);
        var access = SrcFile("DeskGuest.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("ShowPage(\"chat\")", access);
        var shell = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("OpenChatThread(capturedChatId)", shell);
    }

    [Fact]
    public void Thread_IsNoLongerEmbeddedOnHome()
    {
        var shell = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.DoesNotContain("BuildChatPanel", shell);
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.DoesNotContain("BuildChatPanel", chat);
        Assert.DoesNotContain("Close chat", shell);
    }

    [Fact]
    public void ChatPage_ComposesTimelineScroll_AndPinnedComposer()
    {
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        // The timeline scrolls inside the page; the composer is
        // the page's last row, not part of the scroll.
        Assert.Contains("VerticalScrollBarVisibility = ScrollBarVisibility.Auto", chat);
        Assert.Contains("scroller.ScrollToEnd()", chat);
        Assert.Contains("Grid.SetRow(composerStack, 3)", chat);
        Assert.Contains("Grid.SetRow(scroller, 2)", chat);
    }

    [Fact]
    public void HostScroller_StandsDown_AndPageFillsTheViewport()
    {
        var shell = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("page == \"chat\" ? ScrollBarVisibility.Disabled", shell);
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("private void FitChatPage()", chat);
        Assert.Contains("_pageScroller.ViewportHeight", chat);
    }

    [Fact]
    public void ChatPage_RebuildsOnlyOnStateChange()
    {
        // The 2s tick must not churn the composer: rendering is
        // signature-guarded, like Home's helpers column.
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("if (signature == _chatPageSignature) return;", chat);
        var shell = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("case \"chat\": RenderChatPage(); break;", shell);
    }
}
