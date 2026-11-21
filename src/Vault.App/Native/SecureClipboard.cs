using System.Runtime.InteropServices;
using System.Windows.Threading;
using SecureVault.Core;

namespace SecureVault.App.Native;

/// <summary>
/// Copies secrets with the Windows "don't record me" formats:
///   ExcludeClipboardContentFromMonitorProcessing: clipboard managers that honour it skip the content
///   CanIncludeInClipboardHistory = 0: kept out of Win+V history
///   CanUploadToCloudClipboard = 0: never synced to other devices
/// The text goes from a pinned char buffer straight into an HGLOBAL, with no managed string.
/// It's cleared after a timeout, but only if the clipboard still holds our content.
/// Third-party clipboard managers may ignore these flags (see README).
/// </summary>
internal static class SecureClipboard
{
    private static uint _ourSequence;
    private static DispatcherTimer? _timer;

    private static readonly uint FmtExclude = NativeMethods.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing");
    private static readonly uint FmtHistory = NativeMethods.RegisterClipboardFormatW("CanIncludeInClipboardHistory");
    private static readonly uint FmtCloud = NativeMethods.RegisterClipboardFormatW("CanUploadToCloudClipboard");

    public static void CopySecret(ProtectedText text, int clearAfterSeconds)
    {
        bool done = false;
        text.UseChars(chars => done = SetText(chars));
        if (!done) throw new InvalidOperationException("The clipboard is busy. Try again.");
        StartTimer(clearAfterSeconds);
    }

    public static void CopyPlain(string s, int clearAfterSeconds)
    {
        if (!SetText(s.AsSpan())) throw new InvalidOperationException("The clipboard is busy. Try again.");
        StartTimer(clearAfterSeconds);
    }

    private static void StartTimer(int seconds)
    {
        _timer?.Stop();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(seconds) };
        _timer.Tick += (_, _) => { _timer!.Stop(); ClearIfOurs(); };
        _timer.Start();
    }

    private static bool SetText(ReadOnlySpan<char> chars)
    {
        if (!Open()) return false;
        try
        {
            if (!NativeMethods.EmptyClipboard()) return false;
            // Fail closed: if the "don't record" markers can't be set, don't put the secret on the clipboard.
            if (!SetDword(FmtExclude, 0) || !SetDword(FmtHistory, 0) || !SetDword(FmtCloud, 0)) { NativeMethods.EmptyClipboard(); return false; }

            nuint bytes = (nuint)((chars.Length + 1) * sizeof(char));
            nint h = NativeMethods.GlobalAlloc(NativeMethods.GMEM_MOVEABLE, bytes);
            if (h == 0) { NativeMethods.EmptyClipboard(); return false; }
            nint p = NativeMethods.GlobalLock(h);
            if (p == 0) { NativeMethods.GlobalFree(h); NativeMethods.EmptyClipboard(); return false; }
            CopyChars(chars, p);
            NativeMethods.GlobalUnlock(h);
            if (NativeMethods.SetClipboardData(NativeMethods.CF_UNICODETEXT, h) == 0) { NativeMethods.GlobalFree(h); NativeMethods.EmptyClipboard(); return false; }
            _ourSequence = NativeMethods.GetClipboardSequenceNumber();
            return true;
        }
        finally { NativeMethods.CloseClipboard(); }
    }

    private static void CopyChars(ReadOnlySpan<char> chars, nint dest)
    {
        // Copy through a small pinned buffer so no managed string is created.
        char[] tmp = VaultCrypto.AllocSecretChars(chars.Length + 1);
        try
        {
            chars.CopyTo(tmp);
            Marshal.Copy(tmp, 0, dest, tmp.Length);
        }
        finally { VaultCrypto.Wipe(tmp); }
    }

    private static bool SetDword(uint fmt, int value)
    {
        if (fmt == 0) return false;
        nint h = NativeMethods.GlobalAlloc(NativeMethods.GMEM_MOVEABLE, 4);
        if (h == 0) return false;
        nint p = NativeMethods.GlobalLock(h);
        if (p == 0) { NativeMethods.GlobalFree(h); return false; }
        Marshal.WriteInt32(p, value);
        NativeMethods.GlobalUnlock(h);
        if (NativeMethods.SetClipboardData(fmt, h) == 0) { NativeMethods.GlobalFree(h); return false; }
        return true;
    }

    /// <summary>Empty the clipboard if nothing else has been copied since our last copy.</summary>
    public static void ClearIfOurs()
    {
        _timer?.Stop();
        if (_ourSequence == 0 || NativeMethods.GetClipboardSequenceNumber() != _ourSequence) return;
        if (!Open()) return;
        try { NativeMethods.EmptyClipboard(); }
        finally { NativeMethods.CloseClipboard(); }
        _ourSequence = 0;
    }

    /// <summary>Open the clipboard owned by our main window (with a NULL owner, SetClipboardData after EmptyClipboard fails).</summary>
    private static bool Open()
    {
        nint owner = 0;
        try
        {
            if (System.Windows.Application.Current?.MainWindow is { } w)
                owner = new System.Windows.Interop.WindowInteropHelper(w).Handle;
        }
        catch { owner = 0; }
        for (int i = 0; i < 10; i++)
        {
            if (NativeMethods.OpenClipboard(owner)) return true;
            Thread.Sleep(20);
        }
        return false;
    }
}
