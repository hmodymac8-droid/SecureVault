using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App.Windows;

public sealed class EntryRow(VaultEntry e)
{
    public VaultEntry Entry { get; } = e;
    public string Title => Entry.Title;
    public string Username => Entry.Username;
    public string Url => Entry.Url;
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The guard is disposed in the Closed handler, and the window owns its lifetime.")]
public sealed class MainWindow : HardenedWindow
{
    private readonly AppConfig _config = AppConfig.Load();
    private VaultSession? _session;
    private readonly SessionGuard _guard;
    private int _failures;

    // Panels
    private readonly Grid _root = new();
    private readonly StackPanel _startPanel = new() { Margin = new Thickness(30), MaxWidth = 560 };
    private readonly StackPanel _unlockPanel = new() { Margin = new Thickness(30), MaxWidth = 560 };
    private readonly DockPanel _vaultPanel = new() { Margin = new Thickness(8) };

    // Start/unlock controls
    private readonly CheckBox _chkTpm = new() { Content = "Bind to this PC's TPM (needs password + this PC; the recovery key works anywhere)" };
    private readonly CheckBox _chkKeyfile = new() { Content = "Also require a keyfile (keep it on a USB stick, with a backup)" };
    private readonly CheckBox _chkSecureDesktop = new() { Content = "Type the master password on the secure desktop (recommended)" };
    private readonly TextBlock _unlockPath = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Gray, Margin = new Thickness(4) };
    private readonly TextBox _keyfilePath = new() { IsReadOnly = true };
    private readonly StackPanel _keyfileRow = new() { Orientation = Orientation.Vertical };
    private readonly Button _btnUnlock = new() { Content = "Unlock", IsDefault = true, FontWeight = FontWeights.SemiBold };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 10, 4, 4), Foreground = Brushes.DarkRed };

    // Vault controls
    private readonly ObservableCollection<EntryRow> _rows = [];
    private readonly ListView _list = new();
    private readonly TextBox _search = new() { Width = 220 };

    private string VaultPath => _config.LastVaultPath ?? AppConfig.DefaultVaultPath;

    public MainWindow()
    {
        Title = "SecureVault";
        Width = 900; Height = 600; MinWidth = 640; MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Content = _root;
        _root.Children.Add(_startPanel);
        _root.Children.Add(_unlockPanel);
        _root.Children.Add(_vaultPanel);
        _chkSecureDesktop.IsChecked = _config.UseSecureDesktop;
        _chkSecureDesktop.Checked += (_, _) => SaveSecureDesktopPref();
        _chkSecureDesktop.Unchecked += (_, _) => SaveSecureDesktopPref();

        BuildStart();
        BuildUnlock();
        BuildVault();
        _guard = new SessionGuard(this, () => _session?.Data.Settings, Lock);
        Closed += (_, _) => { Lock(""); _guard.Dispose(); };
        Loaded += (_, _) => ShowInitial();
    }

    private void SaveSecureDesktopPref()
    {
        _config.UseSecureDesktop = _chkSecureDesktop.IsChecked == true;
        _config.Save();
    }

    private void ShowInitial()
    {
        if (Hardening.Failed.Count > 0)
            _status.Text = "Some hardening steps couldn't be applied: " + string.Join("; ", Hardening.Failed);
        if (File.Exists(VaultPath)) ShowUnlock(); else Show(_startPanel);
    }

    private void Show(UIElement panel)
    {
        foreach (UIElement c in _root.Children) c.Visibility = c == panel ? Visibility.Visible : Visibility.Collapsed;
        // The secure-desktop checkbox and the status line are shared, and a WPF element can only have one
        // parent, so move them into whichever panel is shown. Detach both first so the indexes are stable.
        if (_status.Parent is Panel sp) sp.Children.Remove(_status);
        if (_chkSecureDesktop.Parent is Panel p) p.Children.Remove(_chkSecureDesktop);
        if (panel == _startPanel) _startPanel.Children.Insert(_startPanel.Children.Count - 1, _chkSecureDesktop); // just above the buttons
        if (panel == _unlockPanel) _unlockPanel.Children.Insert(2, _chkSecureDesktop);
        if (panel is Panel target && panel != _vaultPanel) target.Children.Add(_status);
    }

    private static TextBlock Heading(string s) => new() { Text = s, FontSize = 22, FontWeight = FontWeights.SemiBold, Margin = new Thickness(4, 0, 4, 12) };
    private static TextBlock Para(string s) => new() { Text = s, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 2, 4, 8) };

    // ───────────────────────────── Create ─────────────────────────────

    private void BuildStart()
    {
        var create = new Button { Content = "Create new vault", IsDefault = true, FontWeight = FontWeights.SemiBold };
        var open = new Button { Content = "Open existing vault…" };
        create.Click += async (_, _) => await CreateVault();
        open.Click += (_, _) => PickVault();
        _startPanel.Children.Add(Heading("Create your vault"));
        _startPanel.Children.Add(Para("Your passwords are encrypted on this PC with XChaCha20-Poly1305, under a key derived from your master password with Argon2id. Nothing is ever sent over the network."));
        _startPanel.Children.Add(_chkTpm);
        _startPanel.Children.Add(_chkKeyfile);
        _startPanel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Children = { create, open } });
        if (!TpmProtector.IsAvailable(out string why)) { _chkTpm.IsEnabled = false; _chkTpm.ToolTip = "No TPM available: " + why; }
    }

    private async Task CreateVault()
    {
        char[]? pw = null, again = null;
        byte[]? utf8 = null, keyfileHash = null;
        try
        {
            while (true)
            {
                pw = await PasswordInput.AskAsync(this, "New master password",
                    $"Choose a master password (at least {PasswordStrength.MinLength} characters; several random words are ideal). It can't be recovered without your recovery key.",
                    _config.UseSecureDesktop);
                if (pw is null) return;
                var (ok, msg) = PasswordStrength.CheckMaster(pw);
                if (ok) break;
                VaultCrypto.Wipe(pw);
                MessageBox.Show(this, msg, "Master password too weak", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            again = await PasswordInput.AskAsync(this, "Confirm master password", "Type the master password again.", _config.UseSecureDesktop);
            if (again is null) return;
            if (!CryptographicOperations.FixedTimeEquals(System.Runtime.InteropServices.MemoryMarshal.AsBytes(pw.AsSpan()), System.Runtime.InteropServices.MemoryMarshal.AsBytes(again.AsSpan())))
            {
                MessageBox.Show(this, "The passwords don't match.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            utf8 = Secrets.ToUtf8(pw);

            if (_chkKeyfile.IsChecked == true)
            {
                var dlg = new SaveFileDialog { Title = "Save new keyfile (ideally on a USB stick)", FileName = "SecureVault.key", Filter = "Keyfile|*.key|All files|*.*" };
                if (dlg.ShowDialog(this) != true) return;
                if (File.Exists(dlg.FileName)) { MessageBox.Show(this, "Choose a new file name; existing files are never overwritten."); return; }
                Keyfile.Create(dlg.FileName);
                keyfileHash = Keyfile.Hash(dlg.FileName);
                MessageBox.Show(this, "Keyfile created. Make a second copy on another USB stick. Without the keyfile, only the recovery key can open the vault.", "Keyfile", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            bool tpm = _chkTpm.IsChecked == true;
            _status.Foreground = Brushes.Gray;
            _status.Text = "Tuning Argon2id to this PC and creating the vault…";
            IsEnabled = false;
            AppConfig.EnsurePrivateDir(Path.GetDirectoryName(VaultPath)!);
            string path = VaultPath;
            var req = new UnlockRequest { PasswordUtf8 = utf8, KeyfileHash = keyfileHash, Device = tpm ? new TpmProtector() : null };
            var (session, recovery) = await Task.Run(() =>
            {
                using (req) return VaultSession.Create(path, req, tpm, VaultCrypto.Calibrate(TimeSpan.FromSeconds(1)));
            });
            utf8 = null; keyfileHash = null; // wiped by req.Dispose
            IsEnabled = true;
            _status.Text = "";
            Attach(session);
            if (!ShowKit(recovery)) return;
            ShowVault();
        }
        catch (Exception e)
        {
            IsEnabled = true;
            _status.Foreground = Brushes.DarkRed;
            _status.Text = "Couldn't create the vault: " + e.Message;
        }
        finally
        {
            if (pw is not null) VaultCrypto.Wipe(pw);
            if (again is not null) VaultCrypto.Wipe(again);
            if (utf8 is not null) VaultCrypto.Wipe(utf8);
            if (keyfileHash is not null) VaultCrypto.Wipe(keyfileHash);
        }
    }

    // ───────────────────────────── Unlock ─────────────────────────────

    private void BuildUnlock()
    {
        var pickKey = new Button { Content = "Choose keyfile…" };
        var clearKey = new Button { Content = "No keyfile" };
        pickKey.Click += (_, _) =>
        {
            var d = new OpenFileDialog { Title = "Choose your keyfile" };
            if (d.ShowDialog(this) == true) _keyfilePath.Text = d.FileName;
        };
        clearKey.Click += (_, _) => _keyfilePath.Text = "";
        _keyfileRow.Children.Add(Para("Keyfile (needed if your unlock method uses one):"));
        _keyfileRow.Children.Add(_keyfilePath);
        _keyfileRow.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Children = { pickKey, clearKey } });

        var recovery = new Button { Content = "Use recovery key…" };
        var other = new Button { Content = "Open another vault…" };
        var create = new Button { Content = "Create new vault…" };
        _btnUnlock.Click += async (_, _) => await Unlock(useRecovery: false);
        recovery.Click += async (_, _) => await Unlock(useRecovery: true);
        other.Click += (_, _) => PickVault();
        create.Click += (_, _) =>
        {
            if (MessageBox.Show(this, "Create a separate new vault? Your existing vault file is kept, but SecureVault will switch to the new one.", "New vault", MessageBoxButton.OKCancel) != MessageBoxResult.OK) return;
            var d = new SaveFileDialog { Title = "Where should the new vault go?", FileName = "vault.pmv", Filter = "SecureVault|*.pmv" };
            if (d.ShowDialog(this) != true || File.Exists(d.FileName)) return;
            _config.LastVaultPath = d.FileName; _config.Save();
            Show(_startPanel);
        };

        _unlockPanel.Children.Add(Heading("Unlock your vault"));
        _unlockPanel.Children.Add(_unlockPath);
        _unlockPanel.Children.Add(_keyfileRow);
        _unlockPanel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Children = { _btnUnlock, recovery } });
        _unlockPanel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Children = { other, create } });
    }

    private void ShowUnlock()
    {
        _unlockPath.Text = VaultPath;
        try
        {
            var h = VaultFile.ReadHeader(VaultPath, KdfPolicy.Production);
            _keyfileRow.Visibility = h.Slots.Any(s => s.Keyfile) ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception e) { _status.Text = "This file can't be opened: " + e.Message; }
        Show(_unlockPanel);
        _btnUnlock.Focus();
    }

    private void PickVault()
    {
        var d = new OpenFileDialog { Title = "Open vault", Filter = "SecureVault|*.pmv|All files|*.*" };
        if (d.ShowDialog(this) != true) return;
        _config.LastVaultPath = d.FileName; _config.Save();
        ShowUnlock();
    }

    private async Task Unlock(bool useRecovery)
    {
        char[]? input = null;
        UnlockRequest? req = null;
        try
        {
            string path = VaultPath;
            var header = VaultFile.ReadHeader(path, KdfPolicy.Production);
            if (useRecovery)
            {
                // The recovery key gets around every other factor, so it goes on the secure desktop too.
                input = await PasswordInput.AskAsync(this, "Recovery key", "Type the recovery key from your emergency kit (dashes and case don't matter).", _config.UseSecureDesktop);
                if (input is null) return;
                var secret = RecoveryKey.TryParse(input);
                if (secret is null) { _status.Text = "That isn't a valid recovery key. Check for typos."; return; }
                req = new UnlockRequest { RecoveryKey = secret };
            }
            else
            {
                input = await PasswordInput.AskAsync(this, "Unlock SecureVault", "Enter your master password.", _config.UseSecureDesktop);
                if (input is null) return;
                byte[]? kf = string.IsNullOrEmpty(_keyfilePath.Text) ? null : Keyfile.Hash(_keyfilePath.Text);
                req = new UnlockRequest
                {
                    PasswordUtf8 = Secrets.ToUtf8(input), KeyfileHash = kf,
                    Device = header.Slots.Any(s => s.UsesTpm) ? new TpmProtector() : null,
                };
            }

            IsEnabled = false;
            _status.Foreground = Brushes.Gray;
            _status.Text = "Unlocking…";
            var r = req;
            var session = await Task.Run(() => VaultSession.Open(path, r));

            var (rb, seen) = RollbackGuard.Check(session.Header);
            if (rb == RollbackGuard.Status.Older)
            {
                var ans = MessageBox.Show(this,
                    $"WARNING: this vault file is OLDER than one you've opened before (version {session.Header.Counter} < {seen}).\n\n" +
                    "Someone may have swapped in an old copy, for example one from before a password change, or you restored a backup.\n\n" +
                    "Open it anyway?", "Possible rollback", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                if (ans != MessageBoxResult.Yes) { session.Dispose(); _status.Text = "Not opened."; return; }
                session.Header.Counter = seen; // the next save continues from the highest version seen
            }
            else if (rb == RollbackGuard.Status.NeverSeenHere)
            {
                var ans = MessageBox.Show(this,
                    $"This PC has no record of this vault (version {session.Header.Counter}), so it can't check whether this is the newest copy.\n\n" +
                    "That's normal on a new PC or after reinstalling Windows. If you expected this PC to know the vault, its record may have been deleted, and an old copy could have been swapped in.\n\n" +
                    "Open it?", "Can't check vault version", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.Yes);
                if (ans != MessageBoxResult.Yes) { session.Dispose(); _status.Text = "Not opened."; return; }
            }

            _failures = 0;
            _status.Text = "";
            Attach(session);

            // A recovery key that was never confirmed (the kit window was closed by a lock or a crash) is
            // treated as unknown: issue a new one now. No exposure, so no data-key rotation is needed.
            if (session.Data.Settings.RecoveryKitPending)
            {
                MessageBox.Show(this, "Your last recovery key was never confirmed as saved, so a new one will be shown now. The old one no longer works.",
                    "Recovery key", MessageBoxButton.OK, MessageBoxImage.Information);
                string fresh = session.ReissueUnconfirmedRecoveryKey();
                if (!ShowKit(fresh)) return;
            }

            ShowVault();
            if (useRecovery)
                MessageBox.Show(this, "Opened with the recovery key. If you lost your password, keyfile or PC, open Security and set up a new unlock method now.\n\nIf the recovery key itself may have been seen by someone else, use Security → New recovery key.", "Recovered", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (VaultAuthException e)
        {
            _failures++;
            _status.Foreground = Brushes.DarkRed;
            int delay = Math.Min(30, 1 << Math.Min(_failures - 1, 5));
            _status.Text = e.Message + (_failures > 1 ? $" Wait {delay}s." : "");
            // This delay only slows guessing inside the app. Argon2id is what protects a stolen file.
            if (_failures > 1) { _btnUnlock.IsEnabled = false; await Task.Delay(TimeSpan.FromSeconds(delay)); _btnUnlock.IsEnabled = true; }
        }
        catch (Exception e)
        {
            _status.Foreground = Brushes.DarkRed;
            _status.Text = "Couldn't open the vault: " + e.Message;
        }
        finally
        {
            IsEnabled = true;
            if (input is not null) VaultCrypto.Wipe(input);
            req?.Dispose();
        }
    }

    /// <summary>Show the emergency kit for the current session. Returns false if the vault got locked meanwhile.</summary>
    internal bool ShowKit(string key)
    {
        if (_session is null) return false;
        new RecoveryKitWindow(key, _session) { Owner = this }.ShowDialog();
        return _session is not null;
    }

    private void Attach(VaultSession s)
    {
        _session = s;
        s.Saved += RollbackGuard.Record;
        RollbackGuard.Record(s.Header);
        _guard.ResetIdle();
    }

    // ───────────────────────────── Vault view ─────────────────────────────

    private void BuildVault()
    {
        var bar = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
        Button B(string text, Action a) { var b = new Button { Content = text }; b.Click += (_, _) => Guarded(a); bar.Children.Add(b); return b; }
        bar.Children.Add(new TextBlock { Text = "Search:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4) });
        bar.Children.Add(_search);
        _search.TextChanged += (_, _) => Refresh();
        B("Add", () => Edit(null));
        B("Edit", () => { if (Selected is { } r) Edit(r.Entry); });
        B("Delete", Delete);
        B("Copy user", () => { if (Selected is { } r) SecureClipboard.CopyPlain(r.Username, Settings.ClipboardClearSeconds); });
        B("Copy password", () => { if (Selected is { } r) { SecureClipboard.CopySecret(r.Entry.Password, Settings.ClipboardClearSeconds); Flash($"Password copied; the clipboard clears in {Settings.ClipboardClearSeconds}s."); } });
        B("Import CSV…", ImportCsv);
        B("Security…", () => new SecurityWindow(_session!, _config, this) { Owner = this }.ShowDialog());
        B("Lock", () => Lock("Locked."));

        var grid = new GridView();
        grid.Columns.Add(new GridViewColumn { Header = "Title", Width = 260, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(EntryRow.Title)) });
        grid.Columns.Add(new GridViewColumn { Header = "Username", Width = 240, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(EntryRow.Username)) });
        grid.Columns.Add(new GridViewColumn { Header = "URL", Width = 300, DisplayMemberBinding = new System.Windows.Data.Binding(nameof(EntryRow.Url)) });
        _list.View = grid;
        _list.ItemsSource = _rows;
        _list.MouseDoubleClick += (_, _) => Guarded(() => { if (Selected is { } r) Edit(r.Entry); });

        DockPanel.SetDock(bar, Dock.Top);
        _vaultPanel.Children.Add(bar);
        var footer = new TextBlock { Foreground = Brushes.Gray, Margin = new Thickness(4) };
        DockPanel.SetDock(footer, Dock.Bottom);
        _vaultPanel.Children.Add(footer);
        _vaultPanel.Children.Add(_list);
        _footer = footer;
    }

    private TextBlock _footer = new();
    private VaultSettings Settings => _session!.Data.Settings;
    private EntryRow? Selected => _list.SelectedItem as EntryRow;

    private void Flash(string msg) => _footer.Text = msg;

    private void Guarded(Action a)
    {
        try { a(); }
        catch (Exception e) { MessageBox.Show(this, e.Message, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void ShowVault()
    {
        Refresh();
        Flash($"Unlocked {VaultPath}. Auto-locks after {Settings.AutoLockMinutes} min idle."
              + (_config.UseSecureDesktop ? "" : "   ⚠ Secure desktop is OFF: the master password is typed where keyloggers can see it."));
        Show(_vaultPanel);
        _search.Focus();
    }

    private void Refresh()
    {
        _rows.Clear();
        if (_session is null) return;
        string q = _search.Text.Trim();
        foreach (var e in _session.Data.Entries.OrderBy(e => e.Title, StringComparer.CurrentCultureIgnoreCase))
            if (q.Length == 0 || e.Title.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                || e.Username.Contains(q, StringComparison.CurrentCultureIgnoreCase) || e.Url.Contains(q, StringComparison.CurrentCultureIgnoreCase))
                _rows.Add(new EntryRow(e));
    }

    private void Edit(VaultEntry? entry)
    {
        var w = new EntryWindow(_session!, entry) { Owner = this };
        if (w.ShowDialog() == true) { _session!.Save(); Refresh(); Flash("Saved."); }
    }

    private void Delete()
    {
        if (Selected is not { } r) return;
        if (MessageBox.Show(this, $"Delete “{r.Title}”? (Older versions stay in the encrypted backups.)", "Delete", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        _session!.Data.Entries.Remove(r.Entry);
        _session.Save();
        Refresh();
    }

    private void ImportCsv()
    {
        var warn = MessageBox.Show(this,
            "Browser password exports are PLAIN TEXT. Anyone or anything that reads the CSV gets every password.\n\n" +
            "After importing, delete the CSV and empty the Recycle Bin. Note that on SSDs even \"secure delete\" tools can't guarantee the data is gone, so export straight to a USB stick or a BitLocker-encrypted drive if you can, and change your most important passwords afterwards.\n\nContinue?",
            "Import CSV", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (warn != MessageBoxResult.OK) return;
        var d = new OpenFileDialog { Filter = "CSV|*.csv" };
        if (d.ShowDialog(this) != true) return;
        var entries = CsvImport.Import(d.FileName, _session!.Protector);
        _session.Data.Entries.AddRange(entries);
        _session.Save();
        Refresh();
        if (MessageBox.Show(this, $"Imported {entries.Count} entries. Move the CSV to the Recycle Bin now?", "Import", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
            Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(d.FileName, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
    }

    // ───────────────────────────── Lock ─────────────────────────────

    /// <summary>Close every other window, clear all fields, wipe the keys, then force a GC.</summary>
    public static bool IsLocking { get; private set; }

    public void Lock(string reason)
    {
        IsLocking = true;
        foreach (Window w in Application.Current.Windows.Cast<Window>().ToList())
            if (w != this) try { w.Close(); } catch { /* closing during shutdown */ }
        IsLocking = false;
        SecureClipboard.ClearIfOurs();
        _rows.Clear();
        _search.Text = "";
        _keyfilePath.Text = "";
        if (_session is not null)
        {
            _session.Saved -= RollbackGuard.Record;
            _session.Dispose();
            _session = null;
        }
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        if (!IsLoaded) return;
        if (WindowState == WindowState.Minimized && reason.Length > 0) { /* stay minimized, locked */ }
        if (File.Exists(VaultPath)) ShowUnlock(); else Show(_startPanel);
        _status.Foreground = Brushes.Gray;
        _status.Text = reason;
    }
}
