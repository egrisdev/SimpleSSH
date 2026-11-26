using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SimpleSSH.Controls;

/// <summary>
/// While a tab is dragged, a lifted, slightly see-through copy of it follows the mouse.
/// </summary>
internal sealed class TabDragAdorner : Adorner
{
    private readonly TabItem _tab;
    private readonly ImageSource _image;
    private readonly Size _size;

    public TabDragAdorner(TabControl tabs, TabItem tab) : base(tabs)
    {
        _tab = tab;
        _size = new Size(tab.ActualWidth, tab.ActualHeight);
        _image = Snapshot(tab, _size);
        IsHitTestVisible = false;
    }

    /// <summary>Where the copy's left edge is, in the tab strip's coordinates.</summary>
    public double Left { get; private set; }

    public void MoveTo(double left)
    {
        var tabs = (FrameworkElement)AdornedElement;
        Left = Math.Max(0, Math.Min(left, tabs.ActualWidth - _size.Width));
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        if (!_tab.IsLoaded || PresentationSource.FromVisual(_tab) is null) return;
        // The tab itself is hidden while dragged, leaving a gap where it will land.
        var slot = _tab.TransformToVisual(AdornedElement).TransformBounds(new Rect(_tab.RenderSize));

        // Lifted a little, with a soft shadow, so it looks picked up.
        var ghost = new Rect(new Point(Left, slot.Top - 2), _size);
        var body = new Rect(ghost.X, ghost.Y, Math.Max(0, ghost.Width - 2), ghost.Height);
        for (int i = 1; i <= 4; i++)
        {
            var shadow = body;
            shadow.Offset(0, 2);
            shadow.Inflate(i, i);
            dc.DrawRoundedRectangle(ShadowBrushes[i - 1], null, shadow, 5 + i, 5 + i);
        }
        dc.PushOpacity(0.92);
        dc.DrawImage(_image, ghost);
        dc.Pop();
    }

    private static readonly Brush[] ShadowBrushes = new byte[] { 0x16, 0x10, 0x0A, 0x05 }
        .Select(a => { var b = new SolidColorBrush(Color.FromArgb(a, 0, 0, 0)); b.Freeze(); return (Brush)b; })
        .ToArray();

    private static ImageSource Snapshot(Visual tab, Size size)
    {
        var dpi = VisualTreeHelper.GetDpi(tab);
        var drawing = new DrawingVisual();
        using (var dc = drawing.RenderOpen())
            dc.DrawRectangle(new VisualBrush(tab) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top },
                null, new Rect(size));
        var bitmap = new RenderTargetBitmap(
            Math.Max(1, (int)Math.Ceiling(size.Width * dpi.DpiScaleX)), Math.Max(1, (int)Math.Ceiling(size.Height * dpi.DpiScaleY)),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        bitmap.Render(drawing);
        bitmap.Freeze();
        return bitmap;
    }
}
