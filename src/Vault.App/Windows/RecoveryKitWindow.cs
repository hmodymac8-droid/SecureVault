using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using SecureVault.Core;

namespace SecureVault.App.Windows;

/// <summary>Shows the emergency-kit recovery key once. The user must confirm they've saved it.</summary>
public sealed class RecoveryKitWindow : HardenedWindow
{
    private readonly string _key;
    private readonly string _vaultId;
    private bool _confirmed;

    /// <param name="session">Confirming calls <see cref="VaultSession.ConfirmRecoveryKit"/>. Until then the vault stays marked
    /// "kit pending", and a new key is issued at the next unlock if this window is lost (auto-lock, crash).</param>
    public RecoveryKitWindow(string recoveryKey, VaultSession session)
    {
        _key = recoveryKey; _vaultId = session.Header.VaultId;
        Title = "Your emergency kit";
        Width = 600; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;

        var keyBox = new TextBox
        {
            Text = recoveryKey, IsReadOnly = true, FontFamily = new FontFamily("Consolas"), FontSize = 20,
            HorizontalContentAlignment = HorizontalAlignment.Center, Padding = new Thickness(8),
        };
        var print = new Button { Content = "Print emergency kit…" };
        print.Click += (_, _) => Print();
        var chk = new CheckBox { Content = "I printed it or wrote it down, and stored it somewhere safe and offline" };
        var done = new Button { Content = "Done", IsEnabled = false, IsDefault = true };
        chk.Checked += (_, _) => done.IsEnabled = true;
        chk.Unchecked += (_, _) => done.IsEnabled = false;
        done.Click += (_, _) =>
        {
            try { session.ConfirmRecoveryKit(); }
            catch (Exception ex) { MessageBox.Show(this, "Couldn't record the confirmation: " + ex.Message + " You'll be shown a new key next time."); }
            _confirmed = true;
            Close();
        };
        Closing += (_, e) =>
        {
            if (_confirmed || MainWindow.IsLocking) return;
            if (MessageBox.Show(this, "If you close without confirming, this key is discarded and a NEW one is issued the next time you unlock. Close anyway?",
                    "Recovery key not saved", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
                e.Cancel = true;
        };
        bool counted = false;
        Loaded += (_, _) => { SessionGuard.RecoveryKitOpen++; counted = true; };
        Closed += (_, _) => { keyBox.Clear(); if (counted) SessionGuard.RecoveryKitOpen--; };

        Content = new StackPanel
        {
            Margin = new Thickness(16),
            Children =
            {
                new TextBlock { Text = "Recovery key", FontSize = 20, FontWeight = FontWeights.SemiBold },
                new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 10), Text =
                    "This key opens your vault on ANY computer, even if you forget your master password, lose your keyfile, or your PC's TPM is reset (motherboard swap, Windows reinstall, TPM cleared).\n\n" +
                    "• Print it or write it on paper. Don't save it as a file or photo, or in email or cloud notes.\n" +
                    "• Keep it somewhere safe, like a locked drawer or with important documents.\n" +
                    "• Anyone who has it AND a copy of your vault file can open your vault. Guard it like cash.\n" +
                    "• It's shown only now. You can generate a new one later under Security." },
                keyBox,
                new StackPanel { Orientation = Orientation.Horizontal, Children = { print } },
                chk,
                new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { done } },
            },
        };
    }

    private void Print()
    {
        var pd = new PrintDialog();
        if (pd.ShowDialog() != true) return;
        var doc = new FlowDocument { PagePadding = new Thickness(60), FontFamily = new FontFamily("Segoe UI"), FontSize = 13, ColumnWidth = double.PositiveInfinity };
        doc.Blocks.Add(new Paragraph(new Run("SecureVault: Emergency Kit")) { FontSize = 24, FontWeight = FontWeights.Bold });
        doc.Blocks.Add(new Paragraph(new Run($"Vault ID: {_vaultId}\nCreated: {DateTime.Now:yyyy-MM-dd}")));
        doc.Blocks.Add(new Paragraph(new Run(_key)) { FontFamily = new FontFamily("Consolas"), FontSize = 22, Margin = new Thickness(0, 20, 0, 20) });
        doc.Blocks.Add(new Paragraph(new Run(
            "How to use: start SecureVault, choose \"Use recovery key…\" and type the key above. Then open Security and set a new password or unlock method.\n\n" +
            "Store this sheet offline in a safe place. Anyone with this sheet and your vault file can read your passwords.")));
        pd.PrintDocument(((IDocumentPaginatorSource)doc).DocumentPaginator, "SecureVault emergency kit");
    }
}
