using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Acp.Shared.Presence;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace Acp.SessionAgent;

/// <summary>
/// FR-105 (W85) — the ghost pointer's ONE drawing code. The real
/// Ghost window (PresenceLayer.BuildGhostWindow) and the Presence
/// page's pointer gallery both render through Build, so the style
/// a user picks in the gallery is the style that drives — never a
/// lookalike. Every style is drawn inside the agent HALO: a ring
/// in the current state's color (the scheme's state color, passed
/// in as haloArgb) — the halo is the triple-coding channel that
/// keeps the ghost instantly distinguishable from the owner's own
/// system cursor, whatever base or colorway is chosen.
///
/// Colorways: Classic (white shape, ink outline), Inverted (ink
/// shape, white outline), Accent (the shape filled with the state
/// color itself, white outline). Geometry is drawn at a 44-unit
/// box, scaled by the scheme's size.
/// </summary>
public static class GhostVisual
{
    private static Color Argb(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    private static readonly Color Ink = Color.FromRgb(0x14, 0x14, 0x1C);

    /// <summary>W117 / F4: <paramref name="parked"/> draws the
    /// signed revision's dimmed parked state — the halo color
    /// pulled through GhostDimming (saturation step) and the
    /// whole visual at the parked opacity. A state behavior of
    /// the renderer: the scheme color passed in is unchanged;
    /// only its parked rendering is dimmed.</summary>
    public static Grid Build(PointerStyle style, int haloArgb, string initial, double scale = 1.0,
        bool parked = false)
    {
        if (parked) haloArgb = GhostDimming.DimmedArgb(haloArgb);
        var halo = new SolidColorBrush(Argb(haloArgb));
        (Brush fill, Brush stroke) = style.Colorway switch
        {
            "Inverted" => ((Brush)new SolidColorBrush(Ink), (Brush)Brushes.White),
            "Accent" => ((Brush)new SolidColorBrush(Argb(haloArgb)), (Brush)Brushes.White),
            _ => ((Brush)Brushes.White, (Brush)new SolidColorBrush(Ink)),
        };
        var size = 44 * scale;
        var grid = new Grid
        {
            Width = size, Height = size, IsHitTestVisible = false,
            Opacity = GhostDimming.OpacityFor(parked),
        };

        // The halo: present for EVERY style — an outer ring in the
        // state's color. For the ring bases the halo ring is drawn
        // at the outer edge and the base's own ring inside it.
        grid.Children.Add(new Ellipse
        {
            Width = size, Height = size,
            Stroke = halo, StrokeThickness = 2.5 * scale,
            Fill = Brushes.Transparent, IsHitTestVisible = false,
        });

        void Add(UIElement e) => grid.Children.Add(e);
        Polygon Poly(string points) => new()
        {
            Points = PointCollection.Parse(points),
            Fill = fill, Stroke = stroke, StrokeThickness = 1.5 * scale,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false,
        };
        Ellipse Circle(double d, Brush f, Brush? s = null, double t = 0) => new()
        {
            Width = d * scale, Height = d * scale, Fill = f,
            Stroke = s, StrokeThickness = t * scale,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false,
        };

        switch (style.Base)
        {
            case "RingInitial":
                Add(Circle(30, new SolidColorBrush(Color.FromArgb(0x33, halo.Color.R, halo.Color.G, halo.Color.B)), halo, 2.5));
                Add(new TextBlock
                {
                    Text = initial, Foreground = halo,
                    FontSize = 15 * scale, FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    IsHitTestVisible = false,
                });
                break;
            case "RingDot":
                Add(Circle(26, fill, stroke, 2));
                Add(Circle(8, halo));
                break;
            case "Arrow":
                Add(Poly("15,9 35,22 25,24 29,37 23.5,39 19,26 14,31"));
                break;
            case "Hand":
                Add(Poly("17,39 17,21 20.5,21 20.5,11 24.5,11 24.5,19 27.5,19 27.5,13.5 31,14.5 31,25 29,33 25,39"));
                break;
            case "Crosshair":
                Add(Circle(24, Brushes.Transparent, stroke, 2.5));
                Add(new Line { X1 = 22 * scale, Y1 = 4 * scale, X2 = 22 * scale, Y2 = 40 * scale, Stroke = stroke, StrokeThickness = 2.5 * scale, IsHitTestVisible = false });
                Add(new Line { X1 = 4 * scale, Y1 = 22 * scale, X2 = 40 * scale, Y2 = 22 * scale, Stroke = stroke, StrokeThickness = 2.5 * scale, IsHitTestVisible = false });
                Add(Circle(6, halo));
                break;
            case "Diamond":
                Add(Poly("22,7 37,22 22,37 7,22"));
                break;
            case "Star":
                Add(Poly("22,6 26,17 38,17 28.5,24.5 32,36 22,29 12,36 15.5,24.5 6,17 18,17"));
                break;
            case "Heart":
                Add(new Path
                {
                    Data = Geometry.Parse("M22,37 C5,25 9.5,7.5 22,16.5 C34.5,7.5 39,25 22,37 Z"),
                    Fill = fill, Stroke = stroke, StrokeThickness = 1.5 * scale,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    IsHitTestVisible = false,
                });
                break;
            case "Chevron":
                Add(new Polyline
                {
                    Points = PointCollection.Parse("14,9 31,22 14,35"),
                    Stroke = stroke, StrokeThickness = 5 * scale,
                    StrokeLineJoin = PenLineJoin.Round,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    IsHitTestVisible = false,
                });
                break;
            default: // Wand
                Add(new Line { X1 = 11 * scale, Y1 = 35 * scale, X2 = 27 * scale, Y2 = 17 * scale, Stroke = stroke, StrokeThickness = 3.5 * scale, IsHitTestVisible = false });
                Add(new Polygon
                {
                    Points = PointCollection.Parse("31,3 33.5,9.5 40,9.5 34.8,13.8 36.8,20.5 31,16.8 25.2,20.5 27.2,13.8 22,9.5 28.5,9.5"),
                    Fill = halo, Stroke = stroke, StrokeThickness = 1.2 * scale,
                    IsHitTestVisible = false,
                });
                break;
        }
        return grid;
    }
}
