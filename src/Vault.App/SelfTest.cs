using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SecureVault.App.Native;
using SecureVault.Core;

namespace SecureVault.App;

/// <summary>
/// `SecureVault.exe --selftest [report.txt]` runs inside the fully hardened, clean-environment process and
/// checks that the hardening holds and that vault operations still work under it. It doesn't touch the
/// user's vault or clipboard.
/// </summary>
internal static partial class SelfTest
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    private const uint PROCESS_VM_READ = 0x0010, PROCESS_VM_WRITE = 0x0020, THREAD_SET_CONTEXT = 0x0010, THREAD_SUSPEND_RESUME = 0x0002;

    public static int Run(bool appAlreadyRunning)
    {
        string report = ReportPath(Environment.GetCommandLineArgs());
        var sb = new StringBuilder();
        bool ok = true;
        void Check(string what, bool pass) { sb.AppendLine((pass ? "PASS  " : "FAIL  ") + what); ok &= pass; }
        // Administrators (e.g. when run from the elevated installer, where PowerShell has SeDebugPrivilege enabled)
        // can open any process regardless of its DACL, by design. Those checks only mean something for a normal user.
        bool elevated = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        void DaclCheck(string what, bool pass)
        {
            if (elevated) sb.AppendLine("SKIP  " + what + " (running as administrator: admins bypass DACLs by design; run --selftest as a normal user to check this)");
            else Check(what, pass);
        }

        foreach (var a in Hardening.Applied) sb.AppendLine("APPLIED " + a);
        foreach (var f in Hardening.Failed) sb.AppendLine("NOT APPLIED " + f);
        Check("all hardening steps applied", Hardening.Failed.Count == 0);
        Check("diagnostics disabled (DOTNET_EnableDiagnostics=0)", Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") == "0");
        int pid = Environment.ProcessId;
        bool pipe = Directory.GetFiles(@"\\.\pipe\").Any(p => p.Contains($"dotnet-diagnostic-{pid}", StringComparison.OrdinalIgnoreCase));
        Check("no diagnostic IPC pipe (memory-dump tools can't attach)", !pipe);

        // DACL checks: even our own process is subject to the access check when opening by id.
        nint hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, false, (uint)pid);
        DaclCheck("process memory read/write denied to the user", hp == 0);
        if (hp != 0) NativeMethods.CloseHandle(hp);

        uint tid = 0;
        using (var ready = new ManualResetEventSlim())
        using (var stop = new ManualResetEventSlim())
        {
            var t = new Thread(() => { tid = NativeMethods.GetCurrentThreadId(); ready.Set(); stop.Wait(); }) { IsBackground = true };
            t.Start();
            ready.Wait();
            nint ht = NativeMethods.OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid);
            DaclCheck("new thread: SetThreadContext/suspend denied to the user", ht == 0);
            if (ht != 0) NativeMethods.CloseHandle(ht);
            nint hm = NativeMethods.OpenThread(THREAD_SET_CONTEXT, false, NativeMethods.GetCurrentThreadId());
            DaclCheck("main thread: SetThreadContext denied to the user", hm == 0);
            if (hm != 0) NativeMethods.CloseHandle(hm);
            stop.Set();
            t.Join();
        }

        // Vault operations under hardening (production KDF floor, thread pool, libsodium loaded from app dir).
        string dir = Path.Combine(Path.GetTempPath(), "svlt-selftest-" + Convert.ToHexString(VaultCrypto.RandomBytes(4)));
        Directory.CreateDirectory(dir);
        var tpm = TpmProtector.IsAvailable(out _) ? new TpmProtector() : null;
        string? tpmKey = null;
        try
        {
            string path = Path.Combine(dir, "v.pmv");
            byte[] Pw() => Encoding.UTF8.GetBytes("self test passphrase 123");
            var kdf = new KdfParams(KdfPolicy.Production.MinMemoryKiB, KdfPolicy.Production.MinPasses);
            VaultSession s;
            using (var r = new UnlockRequest { PasswordUtf8 = Pw(), Device = tpm })
                (s, _) = Task.Run(() => VaultSession.Create(path, r, tpm is not null, kdf)).GetAwaiter().GetResult();
            tpmKey = s.Header.Slots.FirstOrDefault(x => x.UsesTpm)?.TpmKeyName;
            s.Data.Entries.Add(new VaultEntry { Title = "t", Password = ProtectedText.FromChars(s.Protector, "pw"), Notes = ProtectedText.Empty(s.Protector) });
            s.Save();
            var rk = s.ChangePassword(Pw(), Encoding.UTF8.GetBytes("another self test pass 456"), null, tpm, kdf);
            tpmKey = s.Header.Slots.FirstOrDefault(x => x.UsesTpm)?.TpmKeyName;
            s.Dispose();
            GC.Collect();
            using (var r = new UnlockRequest { PasswordUtf8 = Encoding.UTF8.GetBytes("another self test pass 456"), Device = tpm })
            {
                using var s2 = VaultSession.Open(path, r);
                Check("create -> save -> change password -> reopen" + (tpm is not null ? " (with real TPM)" : ""), s2.Data.Entries.Single().Password.RevealToString() == "pw");
            }
            using (var r = new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(rk.RecoveryKey) })
                VaultSession.Open(path, r).Dispose();
            Check("new recovery key opens the vault", true);
        }
        catch (Exception e) { Check("vault operations: " + e.GetType().Name + ": " + e.Message, false); }
        finally
        {
            if (tpmKey is not null) try { tpm!.DeleteKey(tpmKey); } catch { }
            try { Directory.Delete(dir, true); } catch { }
        }


        sb.AppendLine(ok ? "RESULT: PASS" : "RESULT: FAIL");
        File.WriteAllText(report, sb.ToString());
        return ok ? 0 : 1;
    }

    public static string ReportPath(string[] args)
    {
        int idx = Array.IndexOf(args, "--selftest");
        return idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : Path.Combine(Path.GetTempPath(), "SecureVault-selftest.txt");
    }

    /// <summary>
    /// Runs in the self-test LAUNCHER process (after the hardened self-test has finished), because the hardened
    /// process deliberately can't create the anonymous pipes needed to drive a helper process. It uses only a
    /// throwaway test vault. It appends its results to the report and returns false if any check failed.
    /// </summary>
    public static bool RunBridgeChecksInLauncher(string[] args)
    {
        string report = ReportPath(args);
        var sb = new StringBuilder();
        bool ok = true;
        if (Mutex.TryOpenExisting(@"LocalSecureVault-SingleInstance", out var m)) { m.Dispose(); sb.AppendLine("SKIP  browser bridge checks (SecureVault is open; close it to run them)"); }
        else BrowserBridgeChecks((what, pass) => { sb.AppendLine((pass ? "PASS  " : "FAIL  ") + what); ok &= pass; });
        var lines = File.Exists(report) ? File.ReadAllLines(report).ToList() : ["FAIL  hardened self-test wrote no report"];
        int res = lines.FindIndex(l => l.StartsWith("RESULT:", StringComparison.Ordinal));
        bool before = res >= 0 && lines[res] == "RESULT: PASS";
        if (res >= 0) lines.RemoveAt(res);
        lines.AddRange(sb.ToString().TrimEnd().Split(Environment.NewLine));
        lines.Add(before && ok ? "RESULT: PASS" : "RESULT: FAIL");
        File.WriteAllLines(report, lines);
        return before && ok;
    }

    /// <summary>
    /// End-to-end over a real pipe and a real helper process. The helper is started by THIS process (not by
    /// Chrome or Edge), so the bridge must refuse it even though the vault is unlocked and filling is enabled.
    /// </summary>
    private static void BrowserBridgeChecks(Action<string, bool> check)
    {
        const string req = "{\"type\":\"list\",\"origin\":\"https://github.com\"}";
        check("browser helper refuses a different extension ID", CallHelper("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", req).Contains("wrong_extension"));
        check("browser helper reports not_running when the bridge is off", CallHelper(Browser.BrowserIds.ExtensionOrigin, req).Contains("not_running"));

        string dir = Path.Combine(Path.GetTempPath(), "svlt-bridge-" + Convert.ToHexString(VaultCrypto.RandomBytes(4)));
        Directory.CreateDirectory(dir);
        try
        {
            VaultSession s;
            using (var r = new UnlockRequest { PasswordUtf8 = Encoding.UTF8.GetBytes("bridge self test pass") })
                (s, _) = VaultSession.Create(Path.Combine(dir, "b.pmv"), r, false, new KdfParams(KdfPolicy.Production.MinMemoryKiB, KdfPolicy.Production.MinPasses));
            using (s)
            {
                s.Data.Settings.BrowserEnabled = true;
                s.Data.Settings.BrowserConfirmEachFill = false;
                s.Data.Entries.Add(new VaultEntry { Title = "GitHub", Url = "github.com", Username = "octo", Password = ProtectedText.FromChars(s.Protector, "pw"), Notes = ProtectedText.Empty(s.Protector) });
                var owner = new System.Windows.Window();
                var notes = new List<string>();
                using var bridge = new Browser.BrowserBridge(owner, () => s, notes.Add);
                Thread.Sleep(300); // let the pipe server start

                // Run the helper on a worker thread while this (UI) thread pumps the dispatcher, because
                // the bridge answers on the UI thread.
                var frame = new System.Windows.Threading.DispatcherFrame();
                string answer = "";
                Task.Run(() => answer = CallHelper(Browser.BrowserIds.ExtensionOrigin, req)).ContinueWith(_ => frame.Continue = false);
                System.Windows.Threading.Dispatcher.PushFrame(frame);
                check("bridge blocks a helper that wasn't started by Chrome/Edge (even when unlocked)" + (answer.Contains("denied") ? "" : " [got: " + answer + " | " + string.Join("; ", notes) + "]"),
                      answer.Contains("denied") && !answer.Contains("octo") && notes.Any(n => n.Contains("Chrome or Edge", StringComparison.Ordinal)));
            }
        }
        catch (Exception e) { check("browser bridge: " + e.GetType().Name + ": " + e.Message, false); }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    private static string CallHelper(string origin, string json)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, CreateNoWindow = true,
        };
        psi.ArgumentList.Add(origin);
        using var p = System.Diagnostics.Process.Start(psi)!;
        byte[] body = Encoding.UTF8.GetBytes(json);
        var input = p.StandardInput.BaseStream;
        input.Write(BitConverter.GetBytes(body.Length));
        input.Write(body);
        input.Flush();
        p.StandardInput.Close();
        var output = p.StandardOutput.BaseStream;
        byte[] len = new byte[4];
        output.ReadExactly(len);
        byte[] resp = new byte[BitConverter.ToInt32(len)];
        output.ReadExactly(resp);
        p.WaitForExit(10000);
        return Encoding.UTF8.GetString(resp);
    }
}
