using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App.Windows;

/// <summary>
/// Key-slot manager and settings. Every change first re-checks the user's current credentials,
/// so someone walking up to an unlocked PC can't quietly add their own way in.
/// </summary>
internal sealed class SecurityWindow : HardenedWindow
{
    private sealed record SlotRow(KeySlot Slot)
    {
        public string Label => Slot.Label;
        public string Method => Slot.Kind == SlotKind.Recovery ? "Recovery key (emergency kit)"
            : "Password" + (Slot.Keyfile ? " + keyfile" : "") + (Slot.UsesTpm ? " + TPM (one PC)" : "");
        public string Created => Slot.Created.LocalDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
    }

    private readonly VaultSession _s;
    private readonly AppConfig _config;
    private readonly ListView _slots = new() { Height = 170 };
    private readonly TextBox _autoLock = new() { Width = 60 }, _clip = new() { Width = 60 }, _backups = new() { Width = 60 };
    private readonly CheckBox _lockMin = new() { Content = "Lock when minimized" };
    private readonly CheckBox _secureDesk = new() { Content = "Use the secure desktop for password entry" };
    private readonly CheckBox _browser = new() { Content = "Allow the SecureVault browser extension (Chrome / Edge) to fill logins" };
    private readonly CheckBox _browserConfirm = new() { Content = "Ask me here before every browser fill (recommended)", Margin = new Thickness(28, 2, 4, 6) };

    public SecurityWindow(VaultSession s, AppConfig config, Window owner)
    {
        _s = s; _config = config; Owner = owner;
        Title = "Security";
        Width = 680; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;

        var grid = new GridView();
        grid.Columns.Add(new GridViewColumn { Header = "Unlock method", Width = 270, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(SlotRow.Method)) });
        grid.Columns.Add(new GridViewColumn { Header = "Label", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(SlotRow.Label)) });
        grid.Columns.Add(new GridViewColumn { Header = "Created", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(SlotRow.Created)) });
        _slots.View = grid;
        RefreshSlots();

        Button B(string text, Func<Task> a) { var b = new Button { Content = text }; b.Click += async (_, _) => await Guard(a); return b; }
        bool tpmOk = TpmProtector.IsAvailable(out _);
        var addTpm = B("Add TPM unlock for this PC…", () => AddSlot(tpm: true, keyfile: false));
        addTpm.IsEnabled = tpmOk;
        var addKf = B("Add password + keyfile unlock…", () => AddSlot(tpm: false, keyfile: true));
        var addPw = B("Add password-only unlock…", () => AddSlot(tpm: false, keyfile: false));
        var remove = B("Remove selected", RemoveSelected);
        var change = B("Change master password…", ChangePassword);
        var recovery = B("New recovery key…", NewRecovery);

        var st = s.Data.Settings;
        _autoLock.Text = st.AutoLockMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        _clip.Text = st.ClipboardClearSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        _backups.Text = st.MaxBackups.ToString(System.Globalization.CultureInfo.InvariantCulture);
        _lockMin.IsChecked = st.LockOnMinimize;
        _secureDesk.IsChecked = config.UseSecureDesktop;
        _browser.IsChecked = st.BrowserEnabled;
        _browserConfirm.IsChecked = st.BrowserConfirmEachFill;
        var browserHelp = new Button { Content = "Set up the browser extension…", HorizontalAlignment = HorizontalAlignment.Left };
        browserHelp.Click += (_, _) => ShowBrowserSetup();
        var save = B("Save settings", SaveSettings);
        var close = new Button { Content = "Close", IsCancel = true };

        StackPanel Row(string label, TextBox box, string unit) => new()
        {
            Orientation = Orientation.Horizontal,
            Children = { new TextBlock { Text = label, Width = 230, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4) }, box, new TextBlock { Text = unit, VerticalAlignment = VerticalAlignment.Center } },
        };

        Content = new StackPanel
        {
            Margin = new Thickness(14),
            Children =
            {
                H("Unlock methods (key slots)"),
                Note("Each method unlocks the same vault on its own. Add a TPM unlock on each PC you use. The recovery key always works and is the way back in if a device is lost."),
                _slots,
                new WrapPanel { Children = { addTpm, addKf, addPw, remove } },
                new WrapPanel { Children = { change, recovery } },
                H("Settings"),
                Row("Auto-lock after", _autoLock, "minutes idle"),
                Row("Clear clipboard after", _clip, "seconds"),
                Row("Encrypted backups to keep", _backups, $"(in {VaultFile.BackupDirectory(s.Path)})"),
                _lockMin, _secureDesk,
                H("Browser"),
                Note("Fills only on the exact website saved in an entry's URL (https only), only when you click, and only while the vault is unlocked. Keep SecureVault open (not minimized, or turn off \"Lock when minimized\")."),
                _browser, _browserConfirm, browserHelp,
                new TextBlock { Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 8, 4, 4), Text =
                    "Process hardening applied: " + string.Join(", ", Hardening.Applied) + (Hardening.Failed.Count > 0 ? ". Not applied: " + string.Join(", ", Hardening.Failed) : "") },
                new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { save, close } },
            },
        };
    }

    private static TextBlock H(string s) => new() { Text = s, FontSize = 16, FontWeight = FontWeights.SemiBold, Margin = new Thickness(4, 10, 4, 2) };
    private static TextBlock Note(string s) => new() { Text = s, TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Gray, Margin = new Thickness(4, 0, 4, 6) };

    private void RefreshSlots() => _slots.ItemsSource = _s.Header.Slots.Select(x => new SlotRow(x)).ToList();

    private async Task Guard(Func<Task> a)
    {
        try { IsEnabled = false; await a(); }
        catch (Exception e) { MessageBox.Show(this, e.Message, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { IsEnabled = true; RefreshSlots(); }
    }

    /// <summary>Ask for the current master password (plus keyfile if needed) and verify it unlocks this vault.</summary>
    private async Task<byte[]?> Reauthenticate(string why)
    {
        char[]? pw = await PasswordInput.AskAsync(this, "Confirm it's you", why + "\n\nEnter your CURRENT master password.", _config.UseSecureDesktop);
        if (pw is null) return null;
        byte[] utf8 = Secrets.ToUtf8(pw);
        VaultCrypto.Wipe(pw);
        byte[]? kf = null;
        if (_s.Header.Slots.All(x => x.Kind == SlotKind.Recovery || x.Keyfile)) kf = AskKeyfile("Choose your current keyfile");
        bool ok;
        var dev = _s.Header.Slots.Any(x => x.UsesTpm) ? new TpmProtector() : null;
        // Verify without wiping utf8 (the caller still needs it); dispose only the keyfile copy.
        var req = new UnlockRequest { PasswordUtf8 = (byte[])utf8.Clone(), KeyfileHash = kf, Device = dev };
        using (req) ok = await Task.Run(() => _s.VerifyCredentials(req));
        if (!ok)
        {
            VaultCrypto.Wipe(utf8);
            MessageBox.Show(this, "That isn't the current master password (or keyfile).", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }
        return utf8;
    }

    private byte[]? AskKeyfile(string title)
    {
        var d = new OpenFileDialog { Title = title };
        return d.ShowDialog(this) == true ? Keyfile.Hash(d.FileName) : null;
    }

    private async Task AddSlot(bool tpm, bool keyfile)
    {
        byte[]? pw = await Reauthenticate("You're adding a new way to unlock this vault.");
        if (pw is null) return;
        byte[]? kf = null;
        try
        {
            if (keyfile)
            {
                var r = MessageBox.Show(this, "Create a NEW keyfile? (No = use an existing file)", "Keyfile", MessageBoxButton.YesNoCancel);
                if (r == MessageBoxResult.Cancel) return;
                if (r == MessageBoxResult.Yes)
                {
                    var d = new SaveFileDialog { Title = "Save new keyfile (ideally on a USB stick)", FileName = "SecureVault.key" };
                    if (d.ShowDialog(this) != true || File.Exists(d.FileName)) return;
                    Keyfile.Create(d.FileName);
                    kf = Keyfile.Hash(d.FileName);
                }
                else if ((kf = AskKeyfile("Choose keyfile")) is null) return;
            }
            string label = tpm ? $"TPM: {Environment.MachineName}" : keyfile ? "Password + keyfile" : "Password";
            var dev = tpm ? new TpmProtector() : null;
            byte[] p = pw, k = kf!;
            await Task.Run(() => _s.AddPasswordSlot(p, kf is null ? null : k, dev, label));
            string extra = tpm && _s.Header.Slots.Any(x => x.Kind == SlotKind.Password && !x.UsesTpm && !x.Keyfile)
                ? "\n\nYou still have a password-only unlock method, which works on any PC without the TPM. Remove it if you want the TPM to be required."
                : "";
            MessageBox.Show(this, "Unlock method added." + extra, "SecureVault");
        }
        finally
        {
            VaultCrypto.Wipe(pw);
            if (kf is not null) VaultCrypto.Wipe(kf);
        }
    }

    /// <summary>
    /// If any unlock method that will remain uses a keyfile, a re-key needs that keyfile, and the core checks
    /// it's the right one. Returns false if the user cancels (nothing changes; there's no silent downgrade).
    /// </summary>
    private bool KeyfileForRekey(string? removingSlotId, out byte[]? kf)
    {
        kf = null;
        if (!_s.Header.Slots.Any(x => x.Kind == SlotKind.Password && x.Keyfile && x.Id != removingSlotId)) return true;
        kf = AskKeyfile("Choose the keyfile used by your keyfile unlock methods");
        return kf is not null;
    }

    /// <summary>After any re-key: report dropped other-PC TPM slots, show the NEW emergency kit, offer to purge old backups.</summary>
    private void AfterRekey(VaultSession.RekeyResult r, string what)
    {
        string msg = what + "\n\nThe vault's encryption key was rotated, so old copies and old credentials can't open anything saved from now on. A NEW recovery key will be shown next; the old printed one no longer works.";
        if (r.DroppedOtherPcTpmSlots.Count > 0)
            msg += "\n\nThese TPM unlock methods belong to other PCs and were removed (add them again on each PC):\n• " +
                   string.Join("\n• ", r.DroppedOtherPcTpmSlots.Select(d => d.Label));
        MessageBox.Show(this, msg, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Information);

        var main = (MainWindow)Owner;
        if (!main.ShowKit(r.RecoveryKey)) return; // locked meanwhile; the pending kit is re-issued at the next unlock

        if (MessageBox.Show(this,
                "Delete the old encrypted backups in the backups folder?\n\nThey can still be opened with the OLD password or recovery key, and they contain your entries as they were then. Recommended: Yes. Also replace any copies on USB drives.",
                "Old backups", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes) == MessageBoxResult.Yes)
        {
            int n = _s.PurgeBackups();
            MessageBox.Show(this, $"Deleted {n} old backup(s). (On SSDs, deleted data may linger at the hardware level.)", "SecureVault");
        }
    }

    private async Task RemoveSelected()
    {
        if (_slots.SelectedItem is not SlotRow row) return;
        if (row.Slot.Kind == SlotKind.Recovery) { MessageBox.Show(this, "The recovery key can't be removed. Use \"New recovery key\" to replace it."); return; }
        if (MessageBox.Show(this, $"Remove the unlock method “{row.Method}”?\n\nThe vault key will be rotated, so this method can't open future versions even from an old copy.", "Remove", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        byte[]? pw = await Reauthenticate("You're removing an unlock method.");
        if (pw is null) return;
        byte[]? kf = null;
        try
        {
            if (!KeyfileForRekey(row.Slot.Id, out kf)) return;
            byte[]? k = kf;
            var r = await Task.Run(() => _s.RemoveSlot(row.Slot.Id, pw, k, new TpmProtector()));
            AfterRekey(r, "Unlock method removed.");
        }
        finally { VaultCrypto.Wipe(pw); if (kf is not null) VaultCrypto.Wipe(kf); }
    }

    private async Task ChangePassword()
    {
        byte[]? cur = await Reauthenticate("You're changing the master password.");
        if (cur is null) return;
        char[]? n1 = null, n2 = null;
        byte[]? utf8 = null, kf = null;
        try
        {
            while (true)
            {
                n1 = await PasswordInput.AskAsync(this, "New master password", $"Choose a NEW master password (at least {PasswordStrength.MinLength} characters). Tip: 4–5 random words make a strong, memorable one.", _config.UseSecureDesktop);
                if (n1 is null) return;
                if (MasterPasswordAdvice.Accept(this, n1)) break;
                VaultCrypto.Wipe(n1);
            }
            n2 = await PasswordInput.AskAsync(this, "Confirm", "Type the new master password again.", _config.UseSecureDesktop);
            if (n2 is null || !n1.AsSpan().SequenceEqual(n2)) { MessageBox.Show(this, "The passwords don't match."); return; }
            utf8 = Secrets.ToUtf8(n1);
            if (!KeyfileForRekey(null, out kf)) return;
            byte[] u = utf8;
            byte[]? k = kf;
            var kdf = await Task.Run(() => VaultCrypto.Calibrate(TimeSpan.FromSeconds(1)));
            var r = await Task.Run(() => _s.ChangePassword(cur, u, k, new TpmProtector(), kdf));
            AfterRekey(r, "Master password changed.");
        }
        finally
        {
            VaultCrypto.Wipe(cur);
            if (n1 is not null) VaultCrypto.Wipe(n1);
            if (n2 is not null) VaultCrypto.Wipe(n2);
            if (utf8 is not null) VaultCrypto.Wipe(utf8);
            if (kf is not null) VaultCrypto.Wipe(kf);
        }
    }

    private async Task NewRecovery()
    {
        if (MessageBox.Show(this, "Generate a new recovery key? The old printed key will stop working, and the vault key is rotated in case the old one was seen.", "Recovery key", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        byte[]? pw = await Reauthenticate("You're replacing the recovery key.");
        if (pw is null) return;
        byte[]? kf = null;
        try
        {
            if (!KeyfileForRekey(null, out kf)) return;
            byte[]? k = kf;
            var r = await Task.Run(() => _s.ReplaceRecoveryKey(pw, k, new TpmProtector()));
            AfterRekey(r, "Recovery key replaced.");
        }
        finally { VaultCrypto.Wipe(pw); if (kf is not null) VaultCrypto.Wipe(kf); }
    }

    private void ShowBrowserSetup()
    {
        string folder = Path.Combine(AppContext.BaseDirectory, "browser-extension");
        bool registered = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Google\Chrome\NativeMessagingHosts\" + Browser.BrowserIds.HostName) is not null
                       || Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\" + Browser.BrowserIds.HostName) is not null;
        string msg =
            "To add the extension (one time):\n\n" +
            "1. In Chrome open chrome://extensions (in Edge: edge://extensions).\n" +
            "2. Turn on \"Developer mode\" (top right in Chrome, left side in Edge).\n" +
            "3. Click \"Load unpacked\" and choose this folder:\n   " + folder + "\n" +
            "4. Check the ID shown is  " + Browser.BrowserIds.ExtensionId + "\n" +
            "   (if it's different, it isn't our extension: remove it).\n" +
            "5. Pin the SecureVault icon to the toolbar.\n\n" +
            "Then tick \"Allow the SecureVault browser extension\" here and click Save settings.\n\n" +
            "The extension folder is in Program Files, so other programs can't change its code." +
            (registered ? "" : "\n\n⚠ The browser connection isn't registered. Re-run install.ps1 as administrator.") +
            "\n\nOpen the extension folder now?";
        if (MessageBox.Show(this, msg, "Browser extension setup", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes && Directory.Exists(folder))
            System.Diagnostics.Process.Start("explorer.exe", "\"" + folder + "\"");
    }

    private Task SaveSettings()
    {
        var st = _s.Data.Settings;
        if (!int.TryParse(_autoLock.Text, out int a) || a is < 1 or > 120) throw new ArgumentException("Auto-lock must be 1 to 120 minutes.");
        if (!int.TryParse(_clip.Text, out int c) || c is < 5 or > 120) throw new ArgumentException("Clipboard clear must be 5 to 120 seconds.");
        if (!int.TryParse(_backups.Text, out int b) || b is < 0 or > 50) throw new ArgumentException("Backups must be 0 to 50.");
        st.AutoLockMinutes = a; st.ClipboardClearSeconds = c; st.MaxBackups = b; st.LockOnMinimize = _lockMin.IsChecked == true;
        st.BrowserEnabled = _browser.IsChecked == true;
        st.BrowserConfirmEachFill = _browserConfirm.IsChecked == true;
        _s.Save();
        (Owner as MainWindow)?.UpdateBrowserBridge();
        _config.UseSecureDesktop = _secureDesk.IsChecked == true;
        _config.Save();
        MessageBox.Show(this, "Settings saved.", "SecureVault");
        return Task.CompletedTask;
    }
}
