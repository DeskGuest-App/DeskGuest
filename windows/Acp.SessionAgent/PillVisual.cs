using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Acp.Shared.Design;
using Acp.Shared.Presence;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Image = System.Windows.Controls.Image;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace Acp.SessionAgent;

/// <summary>
/// FR-105 (W85) — the pill's ONE composition code. The real Box
/// (PresenceLayer.BoxContent) and the Presence page's always-
/// visible preview both build through BuildPillContent with the
/// same scheme, so the preview is the real pill in the unsaved
/// scheme — not a lookalike. STOP buttons come from
/// CreateStopButton in both places too (the real one additionally
/// carries the W60 click flow, attached by PresenceLayer).
///
/// Geometry is the W72 pill at scale 1 (face Ø72, sentence 21 pt,
/// STOP 152×51) multiplied by the scheme's size; the compact
/// detail form is PresenceComposition.CompactPillLine — name +
/// state word + STOP, at a 64-unit height.
/// </summary>
public static class PillVisual
{
    private static Color Argb(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    public static double HeightFor(PresenceScheme scheme) =>
        (scheme.Detail == PresenceDetail.CompactPill ? 64 : 94) * scheme.SizePct / 100.0;

    /// <summary>W117 / F1: the height THIS pill needs so its
    /// sentence renders WHOLE for this pairing name and branch —
    /// the floor base height at the reference fit (pixel-true),
    /// growing by whole text lines beyond it (PillLayout, the
    /// shared estimator). The controlling branch measures the
    /// board sentence; every other branch measures its branch
    /// sentence (W117 / F2: every branch names the agent, so the
    /// measured text is the rendered text).</summary>
    public static double HeightFor(PresenceScheme scheme, PresenceLaw.Actor actor,
        string name, string stateSentence)
    {
        if (scheme.Detail == PresenceDetail.CompactPill)
            return HeightFor(scheme);
        if (actor == PresenceLaw.Actor.Ai)
            return PillLayout.RequiredHeightForName(scheme, name);
        return PillLayout.RequiredHeight(scheme, stateSentence, "");
    }

    /// <summary>The pill STOP: flat emergency fill in the scheme's
    /// STOP color (the default scheme's value IS the reference
    /// token #DC2626), radius 10, no border; hover/pressed darken.
    /// The Background is template-bound so the triggers repaint
    /// the same surface the template draws (the W72 template).</summary>
    public static Button CreateStopButton(PresenceScheme scheme, bool interactive)
    {
        var compact = scheme.Detail == PresenceDetail.CompactPill;
        var scale = scheme.SizePct / 100.0 * (compact ? 0.8 : 1.0);
        var stop = Argb(scheme.StopArgb);
        var hover = Color.FromRgb(
            (byte)(stop.R * 0.82), (byte)(stop.G * 0.82), (byte)(stop.B * 0.82));
        var factory = new FrameworkElementFactory(typeof(Border));
        factory.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
        factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(10 * scale));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        factory.AppendChild(presenter);
        var template = new ControlTemplate(typeof(Button)) { VisualTree = factory };
        var hoverTrigger = new Trigger { Property = Button.IsMouseOverProperty, Value = true };
        hoverTrigger.Setters.Add(new Setter(Button.BackgroundProperty, new SolidColorBrush(hover)));
        template.Triggers.Add(hoverTrigger);
        var pressedTrigger = new Trigger { Property = Button.IsPressedProperty, Value = true };
        pressedTrigger.Setters.Add(new Setter(Button.BackgroundProperty, new SolidColorBrush(hover)));
        template.Triggers.Add(pressedTrigger);
        return new Button
        {
            Content = Strings.Get("StopEsc"),
            Width = 152 * scale,
            Height = 51 * scale,
            Background = new SolidColorBrush(stop),
            Foreground = Brushes.White,
            FontWeight = FontWeights.Bold,
            FontSize = 19 * scale,
            Template = template,
            Cursor = interactive ? System.Windows.Input.Cursors.Hand : System.Windows.Input.Cursors.Arrow,
            IsHitTestVisible = interactive,
            VerticalAlignment = VerticalAlignment.Center,
        };
    }

    /// <summary>The extracted Board 4 robot-head mark, loaded once
    /// from the embedded resource (moved here from PresenceLayer
    /// so the preview draws the same face). Null when the asset is
    /// missing or undecodable — the caller falls back to the
    /// pairing initial (the W72 ruling-2 fallback).</summary>
    private static BitmapImage? _pillMark;
    private static bool _pillMarkTried;

    public static BitmapImage? LoadPillMark()
    {
        if (_pillMarkTried) return _pillMark;
        _pillMarkTried = true;
        try
        {
            var img = new BitmapImage();
            img.BeginInit();
            img.UriSource = new Uri("pack://application:,,,/deskguest-pill-mark.png");
            img.CacheOption = BitmapCacheOption.OnLoad;
            img.EndInit();
            img.Freeze();
            _pillMark = img;
        }
        catch { _pillMark = null; }
        return _pillMark;
    }

    /// <summary>The face circle at the scheme's scale: cream disc,
    /// the reference's own mark (or the pairing initial as the
    /// named fallback), ring in the state's scheme color — gold
    /// only as the default scheme's controlling trim, exactly as
    /// the layer's pinned expression decides; this builder takes
    /// the ring color as given so preview and layer agree.</summary>
    public static Grid Face(PresenceScheme scheme, string name, Color ring)
    {
        var compact = scheme.Detail == PresenceDetail.CompactPill;
        var d = (compact ? 44 : 72) * scheme.SizePct / 100.0;
        var grid = new Grid { Width = d, Height = d, VerticalAlignment = VerticalAlignment.Center };
        grid.Children.Add(new System.Windows.Shapes.Ellipse
        {
            Width = d, Height = d,
            Fill = new SolidColorBrush(Argb(PresenceLaw.PillFaceCream)),
            IsHitTestVisible = false,
        });
        UIElement glyph;
        var mark = LoadPillMark();
        if (mark is not null && !compact)
        {
            glyph = new Image
            {
                Source = mark,
                Width = d, Height = d,
                Stretch = Stretch.UniformToFill,
                Clip = new EllipseGeometry(new System.Windows.Point(d / 2, d / 2), d / 2, d / 2),
                IsHitTestVisible = false,
            };
            RenderOptions.SetBitmapScalingMode((Image)glyph, BitmapScalingMode.HighQuality);
        }
        else
        {
            glyph = new TextBlock
            {
                Text = PresenceLaw.GhostInitial(name),
                Foreground = new SolidColorBrush(Argb(PresenceLaw.PillBackground)),
                FontSize = (compact ? 19 : 30) * scheme.SizePct / 100.0,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                IsHitTestVisible = false,
            };
        }
        grid.Children.Add(glyph);
        grid.Children.Add(new System.Windows.Shapes.Ellipse
        {
            Width = d, Height = d,
            Stroke = new SolidColorBrush(ring),
            StrokeThickness = 2,
            Fill = Brushes.Transparent,
            IsHitTestVisible = false,
        });
        return grid;
    }

    /// <summary>The pill content grid: face (driver identity), the
    /// sentence, STOP — exactly the lines PresenceComposition
    /// .BoxLines yields, at the scheme's detail level. Full: the
    /// board sentence (PillSentence) while an AI controls, else
    /// the state sentence. Compact: CompactPillLine — the name,
    /// the state WORD, STOP. registerSentence hands the sentence
    /// block back to the layer (its narration refresh surface);
    /// the preview passes null.</summary>
    public static Grid BuildPillContent(
        PresenceScheme scheme, PresenceLaw.Actor actor, string name,
        string stateSentence, Button stop, Color ring,
        Action<TextBlock>? registerSentence = null)
    {
        var compact = scheme.Detail == PresenceDetail.CompactPill;
        var scale = scheme.SizePct / 100.0;
        var lines = PresenceComposition.BoxLines(
            compact ? BoxDetailLevel.CompactMinimum : BoxDetailLevel.Full, hasRoster: false);
        var grid = new Grid { VerticalAlignment = VerticalAlignment.Center };
        // W117 / F1: the content's minimum height is the shared
        // estimator's required height minus the shell's vertical
        // padding and border thickness (W128) — the estimator's
        // heights are total pill heights, border included, and
        // the sentence's lines fit inside the pill by
        // construction, and the shell (SizeToContent height)
        // grows past this minimum if WPF measures taller still.
        if (!compact)
            grid.MinHeight = Math.Max(0,
                HeightFor(scheme, actor, name, stateSentence)
                - (PillLayout.VerticalPadding + PillLayout.ShellBorderVertical) * scale);
        var faceD = (compact ? 44 : 72) * scale;
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(faceD) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        if (lines.Contains(BoxLineKind.DriverName))
        {
            var face = Face(scheme, name, ring);
            Grid.SetColumn(face, 0);
            grid.Children.Add(face);
        }
        if (lines.Contains(BoxLineKind.StateSentence))
        {
            var block = new TextBlock
            {
                FontSize = (compact ? 17 : 21) * scale,
                Foreground = new SolidColorBrush(Argb(PresenceLaw.BoxOnBackground)),
                TextWrapping = TextWrapping.Wrap,
                VerticalAlignment = VerticalAlignment.Center,
                MaxWidth = 350 * scale,
                // W128: the full pill's sentence INK starts at
                // the reference's measured ink left — 99 DIP from
                // the pill's left edge (Board 4 pill crop: ink
                // begins 56 crop px from the pill edge at 1.768
                // DIP/px). The font stack's first-glyph ink sits
                // ~6 DIP inside its layout box (measured live at
                // both the shipped geometry — layout 108, ink
                // 113–114 at W72/W115 — and this lane's: layout
                // 99, ink 105; layout 93, ink 102), so the layout
                // origin is set to 91: trim 2 + padding 9 + face
                // 72 + margin 8, landing the ink at 99 ± ruler
                // noise (the threshold ink ruler wobbles ±3 DIP
                // on the first glyph's anti-aliased stem).
                // The shipped margin 23 put the ink at ~113 — a
                // 14-DIP gap the W72 sheet recorded as 9 by
                // comparing layout to ink. The compact form
                // keeps its shipped 23 (its own geometry, not
                // this surface). Full form also takes the
                // reference's measured line pitch: 17 crop px =
                // 30 DIP between line starts (the font stack's
                // default measured 28 live at W72).
                Margin = new Thickness((compact ? 23 : 8) * scale, 0, 14 * scale, 0),
                LineHeight = compact ? double.NaN : 30 * scale,
                LineStackingStrategy = LineStackingStrategy.BlockLineHeight,
            };
            if (compact)
            {
                var word = actor switch
                {
                    PresenceLaw.Actor.Ai => Strings.Get("PresenceStateWordControlling"),
                    PresenceLaw.Actor.Human => Strings.Get("PresenceStatePerson"),
                    _ => Strings.Get("PresenceStateWordWaiting"),
                };
                var (n, w, _) = PresenceComposition.CompactPillLine(name, word);
                block.Inlines.Add(new Run(n) { FontWeight = FontWeights.Bold });
                block.Inlines.Add(new Run($" · {w}"));
            }
            else if (actor == PresenceLaw.Actor.Ai)
            {
                var (bold, rest) = PresenceComposition.PillSentence(name);
                block.Inlines.Add(new Run(bold) { FontWeight = FontWeights.Bold });
                block.Inlines.Add(new Run(rest));
            }
            else
            {
                block.Text = stateSentence;
            }
            registerSentence?.Invoke(block);
            Grid.SetColumn(block, 1);
            grid.Children.Add(block);
        }
        if (lines.Contains(BoxLineKind.Stop))
        {
            Grid.SetColumn(stop, 2);
            grid.Children.Add(stop);
        }
        return grid;
    }
}
