using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using Microsoft.Win32;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App;

/// <summary>Base window: kept out of screenshots, screen recording and Remote Desktop capture.</summary>
public class HardenedWindow : Window
{
    public HardenedWindow()
    {
        SourceInitialized += (_, _) =>
            NativeMethods.SetWindowDisplayAffinity(new WindowInteropHelper(this).Handle, NativeMethods.WDA_EXCLUDEFROMCAPTURE);
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI");
        FontSize = 13;
    }
}

internal static class Secrets
{
    /// <summary>SecurePassword → pinned UTF-16 chars, with no managed string.</summary>
    public static char[] FromPasswordBox(PasswordBox box)
    {
        using SecureString ss = box.SecurePassword;
        nint p = Marshal.SecureStringToGlobalAllocUnicode(ss);
        try
        {
            char[] chars = VaultCrypto.AllocSecretChars(ss.Length);
            Marshal.Copy(p, chars, 0, ss.Length);
            return chars;
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
    }

    public static byte[] ToUtf8(ReadOnlySpan<char> chars)
    {
        byte[] tmp = VaultCrypto.AllocSecret(Encoding.UTF8.GetMaxByteCount(chars.Length));
        int n = Encoding.UTF8.GetBytes(chars, tmp);
        byte[] exact = VaultCrypto.AllocSecret(n);
        tmp.AsSpan(0, n).CopyTo(exact);
        VaultCrypto.Wipe(tmp);
        return exact;
    }
}

/// <summary>Master-password prompt: on the secure desktop if enabled, otherwise a hardened WPF dialog.</summary>
internal static class PasswordInput
{
    public static async Task<char[]?> AskAsync(Window owner, string title, string message, bool secureDesktop)
    {
        if (secureDesktop)
        {
            try { return await SecureDesktop.PromptAsync(title, message); }
            catch (Exception e)
            {
                MessageBox.Show(owner, "The secure desktop isn't available (" + e.Message + "). Falling back to a normal prompt.", "SecureVault");
            }
        }
        return PasswordDialog.Show(owner, title, message);
    }
}

internal sealed class PasswordDialog : HardenedWindow
{
    private readonly PasswordBox _box = new() { MaxLength = 1024 };
    private char[]? _result;

    private PasswordDialog(string title, string message)
    {
        Title = title;
        Width = 440; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;
        var ok = new Button { Content = "OK", IsDefault = true };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        ok.Click += (_, _) => { _result = Secrets.FromPasswordBox(_box); _box.Clear(); DialogResult = true; };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { ok, cancel } };
        Content = new StackPanel
        {
            Margin = new Thickness(14),
            Children = { new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4) }, _box, buttons },
        };
        Loaded += (_, _) => _box.Focus();
        Closed += (_, _) => _box.Clear();
    }

    public static char[]? Show(Window owner, string title, string message)
    {
        var d = new PasswordDialog(title, message) { Owner = owner };
        return d.ShowDialog() == true ? d._result : null;
    }
}

/// <summary>
/// Auto-lock triggers: idle timeout, Windows lock or logoff, Remote Desktop or console session changes,
/// sleep and hibernate (the hibernation file holds a copy of RAM), minimize, and an attached debugger.
/// </summary>
internal sealed class SessionGuard : IDisposable
{
    private readonly Window _main;
    private readonly Action<string> _lock;
    private readonly Func<VaultSettings?> _settings;
    private readonly DispatcherTimer _timer;
    private DateTime _lastInput = DateTime.UtcNow;

    public SessionGuard(Window main, Func<VaultSettings?> settings, Action<string> lockAction)
    {
        _main = main; _settings = settings; _lock = lockAction;
        InputManager.Current.PreProcessInput += OnInput;
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPower;
        SystemEvents.SessionEnding += OnEnding;
        _main.StateChanged += OnState;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    /// <summary>
    /// Above 0 while an unconfirmed recovery kit is on screen. Idle and minimize locks wait, so a slow
    /// hand-copy of the key isn't cut off. Windows lock, sleep, session changes and debugger detection still
    /// lock. If that closes an unconfirmed kit, a new key is issued at the next unlock (RecoveryKitPending).
    /// </summary>
    public static int RecoveryKitOpen { get; set; }

    public void ResetIdle() => _lastInput = DateTime.UtcNow;

    private void OnInput(object? s, PreProcessInputEventArgs e)
    {
        if (e.StagingItem.Input is KeyboardEventArgs or MouseButtonEventArgs or MouseWheelEventArgs) _lastInput = DateTime.UtcNow;
    }

    private void OnTick(object? s, EventArgs e)
    {
        var st = _settings();
        if (st is null) return;
        if (RecoveryKitOpen == 0 && DateTime.UtcNow - _lastInput > TimeSpan.FromMinutes(st.AutoLockMinutes)) _lock("Locked after inactivity.");
#if !DEBUG
        else if (Hardening.DebuggerAttached()) _lock("A debugger attached to SecureVault, so it was locked.");
#endif
    }

    private void OnSessionSwitch(object? s, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.RemoteConnect
            or SessionSwitchReason.RemoteDisconnect or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.ConsoleConnect)
            _main.Dispatcher.Invoke(() => _lock("Locked because the Windows session changed."));
    }

    private void OnPower(object? s, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend) _main.Dispatcher.Invoke(() => _lock("Locked before sleep/hibernate."));
    }

    private void OnEnding(object? s, SessionEndingEventArgs e) => _main.Dispatcher.Invoke(() => _lock("Locked at sign-out."));

    private void OnState(object? s, EventArgs e)
    {
        if (RecoveryKitOpen == 0 && _main.WindowState == WindowState.Minimized && _settings()?.LockOnMinimize == true) _lock("Locked on minimize.");
    }

    public void Dispose()
    {
        _timer.Stop();
        InputManager.Current.PreProcessInput -= OnInput;
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPower;
        SystemEvents.SessionEnding -= OnEnding;
        _main.StateChanged -= OnState;
    }
}
