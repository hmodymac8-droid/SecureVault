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

    public static int Run()
    {
        var args = Environment.GetCommandLineArgs();
        int idx = Array.IndexOf(args, "--selftest");
        string report = idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : Path.Combine(Path.GetTempPath(), "SecureVault-selftest.txt");
        var sb = new StringBuilder();
        bool ok = true;
        void Check(string what, bool pass) { sb.AppendLine((pass ? "PASS  " : "FAIL  ") + what); ok &= pass; }

        foreach (var a in Hardening.Applied) sb.AppendLine("APPLIED " + a);
        foreach (var f in Hardening.Failed) sb.AppendLine("NOT APPLIED " + f);
        Check("all hardening steps applied", Hardening.Failed.Count == 0);
        Check("diagnostics disabled (DOTNET_EnableDiagnostics=0)", Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") == "0");
        int pid = Environment.ProcessId;
        bool pipe = Directory.GetFiles(@"\\.\pipe\").Any(p => p.Contains($"dotnet-diagnostic-{pid}", StringComparison.OrdinalIgnoreCase));
        Check("no diagnostic IPC pipe (memory-dump tools can't attach)", !pipe);

        // DACL checks: even our own process is subject to the access check when opening by id.
        nint hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, false, (uint)pid);
        Check("process memory read/write denied to the user", hp == 0);
        if (hp != 0) NativeMethods.CloseHandle(hp);

        uint tid = 0;
        using (var ready = new ManualResetEventSlim())
        using (var stop = new ManualResetEventSlim())
        {
            var t = new Thread(() => { tid = NativeMethods.GetCurrentThreadId(); ready.Set(); stop.Wait(); }) { IsBackground = true };
            t.Start();
            ready.Wait();
            nint ht = NativeMethods.OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid);
            Check("new thread: SetThreadContext/suspend denied to the user", ht == 0);
            if (ht != 0) NativeMethods.CloseHandle(ht);
            nint hm = NativeMethods.OpenThread(THREAD_SET_CONTEXT, false, NativeMethods.GetCurrentThreadId());
            Check("main thread: SetThreadContext denied to the user", hm == 0);
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
}
