using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace SecureVault.App.Windows;

/// <summary>"Fill this login in the browser?" It's topmost, Deny is the default, and it auto-denies after 30 seconds.</summary>
public sealed class FillConfirmWindow : HardenedWindow
{
    public FillConfirmWindow(string title, string username, string host)
    {
        Title = "SecureVault: fill login?";
        Width = 440; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;
        Topmost = true;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var allow = new Button { Content = "Allow" };
        var deny = new Button { Content = "Deny", IsDefault = true, IsCancel = true };
        allow.Click += (_, _) => DialogResult = true;
        deny.Click += (_, _) => DialogResult = false;
        var countdown = new TextBlock { Foreground = Brushes.Gray, Margin = new Thickness(4), VerticalAlignment = VerticalAlignment.Center };
        int left = 30;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) => { left--; countdown.Text = $"Denies in {left}s"; if (left <= 0) { timer.Stop(); DialogResult = false; } };
        countdown.Text = $"Denies in {left}s";
        Loaded += (_, _) => { timer.Start(); Activate(); deny.Focus(); };
        Closed += (_, _) => timer.Stop();

        Content = new StackPanel
        {
            Margin = new Thickness(16),
            Children =
            {
                new TextBlock { Text = "Your browser wants to fill a login", FontSize = 16, FontWeight = FontWeights.SemiBold },
                new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 4),
                    Text = $"Site: {host}\nLogin: {title}" + (username.Length > 0 ? $" ({username})" : "") },
                new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Gray, Margin = new Thickness(0, 0, 0, 8),
                    Text = "Only allow this if you just asked SecureVault to fill this site." },
                Footer(countdown, allow, deny),
            },
        };
    }

    private static DockPanel Footer(TextBlock countdown, Button allow, Button deny)
    {
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Children = { allow, deny } };
        DockPanel.SetDock(countdown, Dock.Left);
        DockPanel.SetDock(buttons, Dock.Right);
        return new DockPanel { LastChildFill = false, Children = { countdown, buttons } };
    }
}
