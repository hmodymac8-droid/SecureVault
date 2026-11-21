using System.Drawing;
using System.Runtime.InteropServices;
using SecureVault.Core;
using WinForms = System.Windows.Forms;

namespace SecureVault.App.Native;

/// <summary>
/// Asks for the master password on a separate, freshly created Windows desktop (the KeePass approach).
/// Ordinary user-level keyloggers and screen grabbers hooked into the normal desktop can't see input on
/// another desktop. It doesn't stop kernel-level malware or hardware keyloggers.
///
/// Safety: the original desktop is always switched back in a finally block, and the prompt times out after
/// 60 seconds, so the user can never be stranded on a blank desktop.
/// </summary>
internal static class SecureDesktop
{
    private const int TimeoutSeconds = 60;

    /// <summary>Returns the password in a pinned char buffer (the caller wipes it), or null if cancelled.</summary>
    public static Task<char[]?> PromptAsync(string title, string message)
    {
        var tcs = new TaskCompletionSource<char[]?>();
        nint original = NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId());
        string name = "SecureVault_" + Convert.ToHexString(VaultCrypto.RandomBytes(8));
        const uint access = NativeMethods.DESKTOP_CREATEWINDOW | NativeMethods.DESKTOP_SWITCHDESKTOP | NativeMethods.DESKTOP_READOBJECTS
                          | NativeMethods.DESKTOP_WRITEOBJECTS | NativeMethods.DESKTOP_CREATEMENU | NativeMethods.DESKTOP_HOOKCONTROL;
        nint sd = Hardening.DesktopSecurityDescriptor();
        var sa = new NativeMethods.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>(), lpSecurityDescriptor = sd };
        nint desk = NativeMethods.CreateDesktopW(name, 0, 0, 0, access, ref sa);
        if (sd != 0) NativeMethods.LocalFree(sd);
        if (desk == 0) { tcs.SetException(new InvalidOperationException($"Could not create secure desktop (error {Marshal.GetLastPInvokeError()}).")); return tcs.Task; }

        var t = new Thread(() =>
        {
            char[]? result = null;
            try
            {
                if (!NativeMethods.SetThreadDesktop(desk)) throw new InvalidOperationException("SetThreadDesktop failed.");
                if (!NativeMethods.SwitchDesktop(desk)) throw new InvalidOperationException("SwitchDesktop failed.");
                using var form = new PromptForm(title, message, TimeoutSeconds);
                WinForms.Application.Run(form);
                result = form.Result;
            }
            catch (Exception e) { tcs.TrySetException(e); }
            finally
            {
                NativeMethods.SwitchDesktop(original);
                tcs.TrySetResult(result);
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.IsBackground = true;
        t.Start();

        return tcs.Task.ContinueWith(task =>
        {
            t.Join(TimeSpan.FromSeconds(5));
            NativeMethods.SwitchDesktop(original); // belt and braces
            NativeMethods.CloseDesktop(desk);
            return task.Result;
        }, TaskScheduler.Default);
    }

    private sealed class PromptForm : WinForms.Form
    {
        private readonly WinForms.TextBox _box;
        private readonly WinForms.Timer _timer;
        private int _remaining;
        private readonly WinForms.Label _countdown;
        public char[]? Result { get; private set; }

        public PromptForm(string title, string message, int timeout)
        {
            _remaining = timeout;
            Text = title;
            FormBorderStyle = WinForms.FormBorderStyle.FixedDialog;
            StartPosition = WinForms.FormStartPosition.CenterScreen;
            MaximizeBox = MinimizeBox = false;
            TopMost = true;
            ShowInTaskbar = false;
            Font = new Font("Segoe UI", 10f);
            ClientSize = new Size(440, 190);
            BackColor = Color.White;

            var lbl = new WinForms.Label { Text = message, Left = 16, Top = 14, Width = 410, Height = 44 };
            var note = new WinForms.Label { Text = "🔒 Secure desktop: other apps can't see this screen.", Left = 16, Top = 60, Width = 410, ForeColor = Color.DarkGreen };
            _box = new WinForms.TextBox { Left = 16, Top = 88, Width = 408, UseSystemPasswordChar = true, MaxLength = 1024 };
            _countdown = new WinForms.Label { Left = 16, Top = 146, Width = 200, ForeColor = Color.Gray };
            var ok = new WinForms.Button { Text = "OK", Left = 250, Top = 140, Width = 80, DialogResult = WinForms.DialogResult.OK };
            var cancel = new WinForms.Button { Text = "Cancel", Left = 344, Top = 140, Width = 80, DialogResult = WinForms.DialogResult.Cancel };
            ok.Click += (_, _) => { CaptureText(); Close(); };
            cancel.Click += (_, _) => Close();
            AcceptButton = ok;
            CancelButton = cancel;
            Controls.AddRange([lbl, note, _box, _countdown, ok, cancel]);

            _timer = new WinForms.Timer { Interval = 1000 };
            _timer.Tick += (_, _) =>
            {
                _remaining--;
                _countdown.Text = $"Closes in {_remaining}s";
                if (_remaining <= 0) Close();
            };
            _countdown.Text = $"Closes in {_remaining}s";
            Shown += (_, _) => { Activate(); _box.Focus(); _timer.Start(); };
        }

        /// <summary>Read the edit control's text straight into a pinned buffer with GetWindowText, with no managed string.</summary>
        private void CaptureText()
        {
            int len = NativeMethods.GetWindowTextLengthW(_box.Handle);
            char[] buf = VaultCrypto.AllocSecretChars(len + 1);
            int n = NativeMethods.GetWindowTextW(_box.Handle, buf, buf.Length);
            if (n <= 0) { VaultCrypto.Wipe(buf); return; }
            Result = VaultCrypto.AllocSecretChars(n);
            buf.AsSpan(0, n).CopyTo(Result);
            VaultCrypto.Wipe(buf);
        }

        protected override void OnFormClosing(WinForms.FormClosingEventArgs e)
        {
            _timer.Stop();
            // Overwrite the edit control's internal buffer before it's destroyed.
            // (NUL characters would just truncate it, so use a visible filler.)
            if (_box.IsHandleCreated) _box.Text = new string('x', _box.TextLength);
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _timer.Dispose();
            base.Dispose(disposing);
        }
    }
}
