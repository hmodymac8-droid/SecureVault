using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App.Windows;

/// <summary>
/// Add or edit an entry. Password and notes stay hidden: they're only turned into .NET strings
/// (which can't be wiped) if the user clicks Show.
/// </summary>
public sealed class EntryWindow : HardenedWindow
{
    private readonly VaultSession _s;
    private readonly VaultEntry? _entry;
    private readonly TextBox _title = new(), _user = new(), _url = new();
    private readonly PasswordBox _pw = new() { MaxLength = 4096 };
    private readonly TextBox _pwShown = new() { Visibility = Visibility.Collapsed, FontFamily = new FontFamily("Consolas") };
    private readonly TextBox _notes = new() { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 110, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Visibility = Visibility.Collapsed };
    private readonly Button _showNotes = new() { Content = "Show notes", HorizontalAlignment = HorizontalAlignment.Left };
    private readonly Slider _len = new() { Minimum = 12, Maximum = 64, Value = 24, Width = 160, IsSnapToTickEnabled = true, TickFrequency = 1, VerticalAlignment = VerticalAlignment.Center };
    private readonly CheckBox _sym = new() { Content = "Symbols", IsChecked = true };
    private readonly TextBlock _pwNote = new() { Foreground = Brushes.Gray, Margin = new Thickness(4, 0, 4, 4), TextWrapping = TextWrapping.Wrap };

    /// <summary>Set when the user typed, generated or revealed a new password.</summary>
    private ProtectedText? _newPassword;
    private bool _notesRevealed;

    public EntryWindow(VaultSession s, VaultEntry? entry)
    {
        _s = s; _entry = entry;
        Title = entry is null ? "Add entry" : "Edit entry";
        Width = 520; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;

        _title.Text = entry?.Title ?? "";
        _user.Text = entry?.Username ?? "";
        _url.Text = entry?.Url ?? "";
        _pwNote.Text = entry is null ? "" : "Leave empty to keep the current password.";

        var show = new Button { Content = "Show" };
        show.Click += (_, _) => TogglePassword();
        var copy = new Button { Content = "Copy" };
        copy.Click += (_, _) => { var p = CurrentPassword(); if (p is not null) SecureClipboard.CopySecret(p, _s.Data.Settings.ClipboardClearSeconds); };
        var gen = new Button { Content = "Generate" };
        gen.Click += (_, _) => Generate();
        var lenLabel = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4) };
        lenLabel.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Value") { Source = _len, StringFormat = "{0:0} chars" });

        _showNotes.Click += (_, _) => RevealNotes();
        if (entry is null) RevealNotes();

        var ok = new Button { Content = "Save", IsDefault = true };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        ok.Click += (_, _) => SaveAndClose();

        var pwGrid = new Grid();
        pwGrid.Children.Add(_pw);
        pwGrid.Children.Add(_pwShown);

        Content = new StackPanel
        {
            Margin = new Thickness(14),
            Children =
            {
                Label("Title"), _title, Label("Username"), _user, Label("URL"), _url,
                Label("Password"), pwGrid, _pwNote,
                new StackPanel { Orientation = Orientation.Horizontal, Children = { show, copy, gen, _len, lenLabel, _sym } },
                Label("Notes"), _showNotes, _notes,
                new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { ok, cancel } },
            },
        };
        Loaded += (_, _) => _title.Focus();
        Closed += (_, _) => { _pw.Clear(); _pwShown.Clear(); _notes.Clear(); };
    }

    private static TextBlock Label(string s) => new() { Text = s, Margin = new Thickness(4, 8, 4, 0), FontWeight = FontWeights.SemiBold };

    private ProtectedText? CurrentPassword()
    {
        if (_pwShown.Visibility == Visibility.Visible) return ProtectedText.FromChars(_s.Protector, _pwShown.Text);
        if (_pw.SecurePassword.Length > 0)
        {
            char[] c = Secrets.FromPasswordBox(_pw);
            try { return ProtectedText.FromChars(_s.Protector, c); } finally { VaultCrypto.Wipe(c); }
        }
        return _newPassword ?? _entry?.Password;
    }

    private void TogglePassword()
    {
        if (_pwShown.Visibility == Visibility.Visible)
        {
            _newPassword = ProtectedText.FromChars(_s.Protector, _pwShown.Text);
            _pwShown.Clear();
            _pwShown.Visibility = Visibility.Collapsed;
            _pw.Visibility = Visibility.Visible;
            _pwNote.Text = "Hidden again.";
            return;
        }
        var p = CurrentPassword();
        _pw.Clear();
        _pwShown.Text = p?.RevealToString() ?? ""; // explicit reveal: becomes an unwipeable string
        _pw.Visibility = Visibility.Collapsed;
        _pwShown.Visibility = Visibility.Visible;
        _pwNote.Text = "Visible. Make sure no one is looking.";
    }

    private void Generate()
    {
        char[] g = PasswordGenerator.Generate(new GeneratorOptions((int)_len.Value, Symbols: _sym.IsChecked == true));
        try
        {
            _newPassword = ProtectedText.FromChars(_s.Protector, g);
            _pw.Clear();
            if (_pwShown.Visibility == Visibility.Visible) _pwShown.Text = new string(g);
            var bits = PasswordGenerator.EntropyBits(new GeneratorOptions((int)_len.Value, Symbols: _sym.IsChecked == true));
            _pwNote.Text = $"Generated a {g.Length}-character password (about {bits:F0} bits). Click Show to view it, or Copy.";
        }
        finally { VaultCrypto.Wipe(g); }
    }

    private void RevealNotes()
    {
        if (_notesRevealed) return;
        _notesRevealed = true;
        _notes.Text = _entry?.Notes.RevealToString() ?? "";
        _notes.Visibility = Visibility.Visible;
        _showNotes.Visibility = Visibility.Collapsed;
    }

    private void SaveAndClose()
    {
        if (string.IsNullOrWhiteSpace(_title.Text)) { MessageBox.Show(this, "Give the entry a title."); return; }
        var pw = CurrentPassword() ?? ProtectedText.Empty(_s.Protector);
        var notes = _notesRevealed ? ProtectedText.FromChars(_s.Protector, _notes.Text) : _entry?.Notes ?? ProtectedText.Empty(_s.Protector);
        if (_entry is null)
        {
            _s.Data.Entries.Add(new VaultEntry { Title = _title.Text.Trim(), Username = _user.Text.Trim(), Url = _url.Text.Trim(), Password = pw, Notes = notes });
        }
        else
        {
            _entry.Title = _title.Text.Trim(); _entry.Username = _user.Text.Trim(); _entry.Url = _url.Text.Trim();
            _entry.Password = pw; _entry.Notes = notes; _entry.Modified = DateTimeOffset.UtcNow;
        }
        DialogResult = true;
    }
}
