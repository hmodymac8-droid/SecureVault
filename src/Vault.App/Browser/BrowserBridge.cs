using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App.Browser;

internal static class BrowserIds
{
    /// <summary>The extension's fixed ID, derived from the public key in its manifest.</summary>
    public const string ExtensionId = "mipbfgbdnkehbkfcocihjcilaflfphih";
    public const string ExtensionOrigin = "chrome-extension://" + ExtensionId + "/";
    public const string HostName = "com.securevault.host";

    /// <summary>A per-user pipe name. The pipe itself is also ACL'd to the current user only.</summary>
    public static string PipeName => "SecureVault.Browser." + WindowsIdentity.GetCurrent().User!.Value;

    public const int MaxResponseBytes = 1024 * 1024; // Chrome's limit for host → browser messages

    public static async Task<byte[]?> ReadFrameAsync(Stream s, int max, CancellationToken ct)
    {
        byte[] len = new byte[4];
        if (!await ReadExactAsync(s, len, ct)) return null;
        int n = BinaryPrimitives.ReadInt32LittleEndian(len);
        if (n <= 0 || n > max) throw new InvalidDataException("Bad frame length.");
        byte[] buf = VaultCrypto.AllocSecret(n);
        if (!await ReadExactAsync(s, buf, ct)) { VaultCrypto.Wipe(buf); return null; }
        return buf;
    }

    public static async Task WriteFrameAsync(Stream s, byte[] payload, CancellationToken ct)
    {
        byte[] len = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(len, payload.Length);
        await s.WriteAsync(len, ct);
        await s.WriteAsync(payload, ct);
        await s.FlushAsync(ct);
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int got = 0;
        while (got < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(got), ct);
            if (n == 0) return got == 0 ? false : throw new EndOfStreamException();
            got += n;
        }
        return true;
    }
}

/// <summary>
/// Runs inside the unlocked SecureVault app, only while the vault is unlocked and browser filling is on.
/// It accepts one request per connection on a local named pipe. Before answering, it checks:
///   - the pipe is ACL'd to the current user and rejects remote clients;
///   - the program on the other end is THIS SecureVault.exe (the native helper), started by Chrome or Edge
///     (directly, or through the cmd.exe that Chrome uses to launch native hosts);
///   - a rate limit;
///   - then BrowserProtocol makes every content decision (site match, confirmation).
/// </summary>
internal sealed class BrowserBridge : IDisposable
{
    private readonly Func<VaultSession?> _session;
    private readonly Window _owner;
    private readonly Action<string> _notify;
    private readonly CancellationTokenSource _cts = new();
    private readonly Queue<DateTime> _recent = new();

    public BrowserBridge(Window owner, Func<VaultSession?> session, Action<string> notify)
    {
        _owner = owner; _session = session; _notify = notify;
        _ = Task.Run(() => AcceptLoop(_cts.Token));
    }

    public void Dispose() { _cts.Cancel(); _cts.Dispose(); }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new NamedPipeServerStream(BrowserIds.PipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(ct);
                var p = pipe; pipe = null;
                _ = Task.Run(() => Serve(p, ct), CancellationToken.None);
            }
            catch (OperationCanceledException) { pipe?.Dispose(); return; }
            catch (IOException) { pipe?.Dispose(); await Task.Delay(200, CancellationToken.None); }
            catch (Exception) { pipe?.Dispose(); await Task.Delay(1000, CancellationToken.None); }
        }
    }

    private async Task Serve(NamedPipeServerStream pipe, CancellationToken outer)
    {
        using (pipe)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(outer))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(45)); // includes time for the user to answer a confirmation
            byte[]? req = null, resp = null;
            try
            {
                // Identify the client first. Then read its (size-capped) request even if it'll be refused, so it
                // gets a clear "denied" instead of a broken pipe. Unverified requests are never parsed.
                bool trusted = VerifyClient(pipe, out string why);
                using (var readLimit = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token))
                {
                    readLimit.CancelAfter(TimeSpan.FromSeconds(5));
                    req = await BrowserIds.ReadFrameAsync(pipe, BrowserProtocol.MaxRequestBytes, readLimit.Token);
                }
                if (req is null) return;
                if (!trusted)
                {
                    _owner.Dispatcher.Invoke(() => _notify("Blocked a browser-bridge connection: " + why));
                    resp = Err("denied");
                }
                else if (!RateOk()) resp = Err("busy");
                else
                {
                    byte[] r = req;
                    resp = _owner.Dispatcher.Invoke(() =>
                    {
                        var s = _session();
                        return s is null || s.IsLocked ? Err("locked") : BrowserProtocol.Handle(s, r, (entry, host) => Confirm(entry, host));
                    });
                }
                await BrowserIds.WriteFrameAsync(pipe, resp, timeout.Token);
            }
            catch (Exception) { /* client went away or sent garbage; nothing to report */ }
            finally
            {
                if (req is not null) VaultCrypto.Wipe(req);
                if (resp is not null) VaultCrypto.Wipe(resp);
            }
        }
    }

    private static byte[] Err(string code)
    {
        byte[] b = System.Text.Encoding.UTF8.GetBytes("{\"error\":\"" + code + "\"}");
        byte[] p = VaultCrypto.AllocSecret(b.Length);
        b.CopyTo(p, 0);
        return p;
    }

    private bool RateOk()
    {
        lock (_recent)
        {
            var now = DateTime.UtcNow;
            while (_recent.Count > 0 && now - _recent.Peek() > TimeSpan.FromSeconds(10)) _recent.Dequeue();
            if (_recent.Count >= 30) return false;
            _recent.Enqueue(now);
            return true;
        }
    }

    private bool Confirm(VaultEntry entry, string host)
    {
        if (MainWindowIsLocking()) return false;
        var w = new Windows.FillConfirmWindow(entry.Title, entry.Username, host) { Owner = _owner };
        bool ok = w.ShowDialog() == true;
        _notify(ok ? $"Filled “{entry.Title}” on {host} in the browser." : $"Denied a browser fill on {host}.");
        return ok;
    }

    private static bool MainWindowIsLocking() => Windows.MainWindow.IsLocking;

    // ───────────── Who is on the other end? ─────────────

    private static bool VerifyClient(NamedPipeServerStream pipe, out string why)
    {
        why = "";
        if (!NativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid)) { why = "unknown process"; return false; }
        string? self = Environment.ProcessPath;
        string? client = ImagePath(pid);
        if (self is null || client is null || !string.Equals(Path.GetFullPath(client), Path.GetFullPath(self), StringComparison.OrdinalIgnoreCase))
        {
            why = "it wasn't SecureVault's browser helper (" + Path.GetFileName(client ?? "?") + ")";
            return false;
        }
        // Walk up: helper ← [cmd.exe] ← chrome.exe / msedge.exe
        uint cur = pid;
        for (int depth = 0; depth < 3; depth++)
        {
            uint parent = ParentPid(cur);
            if (parent == 0) break;
            string? img = ImagePath(parent);
            string name = Path.GetFileName(img ?? "").ToLowerInvariant();
            if (name is "chrome.exe" or "msedge.exe") return true;
            if (name != "cmd.exe") break;
            cur = parent;
        }
        why = "the helper wasn't started by Chrome or Edge";
        return false;
    }

    private static string? ImagePath(uint pid)
    {
        nint h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == 0) return null;
        try
        {
            char[] buf = new char[1024];
            int size = buf.Length;
            return NativeMethods.QueryFullProcessImageNameW(h, 0, buf, ref size) ? new string(buf, 0, size) : null;
        }
        finally { NativeMethods.CloseHandle(h); }
    }

    private static uint ParentPid(uint pid)
    {
        nint h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == 0) return 0;
        try
        {
            return NativeMethods.NtQueryInformationProcess(h, 0, out var pbi, Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _) == 0
                ? (uint)pbi.InheritedFromUniqueProcessId : 0;
        }
        finally { NativeMethods.CloseHandle(h); }
    }
}
