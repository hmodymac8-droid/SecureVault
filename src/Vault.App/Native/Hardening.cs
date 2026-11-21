using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SecureVault.App.Native;

/// <summary>Process-level hardening. Each step is best effort and reports what it applied.</summary>
internal static class Hardening
{
    public static readonly List<string> Applied = [];
    public static readonly List<string> Failed = [];

    public static void ApplyEarly()
    {
        // 1. DLL search order: only the app folder and System32. Never the current dir, PATH or %TEMP%.
        Try("DLL search restricted to app dir + System32", () =>
            NativeMethods.SetDefaultDllDirectories(NativeMethods.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | NativeMethods.LOAD_LIBRARY_SEARCH_SYSTEM32)
            && NativeMethods.SetDllDirectoryW(""));

        // 2. Image-load policy: no DLLs from network shares or low-integrity locations; prefer System32 copies.
        Try("Block remote / low-integrity DLLs", () =>
        {
            uint flags = 0b111; // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
            return NativeMethods.SetProcessMitigationPolicy(NativeMethods.ProcessImageLoadPolicy, ref flags, sizeof(uint));
        });

        // 3. Disable legacy extension points (AppInit_DLLs, winsock LSPs, IME injection, etc.).
        Try("Disable legacy DLL extension points", () =>
        {
            uint flags = 1;
            return NativeMethods.SetProcessMitigationPolicy(NativeMethods.ProcessExtensionPointDisablePolicy, ref flags, sizeof(uint));
        });

        // 4. Process DACL (as KeePass does): other processes running as this user can no longer open us
        //    for memory reading, writing or thread injection. Only SYSTEM keeps full access. The OWNER RIGHTS
        //    ACE also strips the owner's implicit WRITE_DAC, so the DACL can't simply be put back.
        //    An administrator with SeDebugPrivilege can still bypass this.
        Try("Restrict process access (DACL)", () =>
        {
            string sid = WindowsIdentity.GetCurrent().User!.Value;
            const string limited = "0x101001"; // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
            string sddl = $"D:P(A;;GA;;;SY)(A;;{limited};;;{sid})(A;;{limited};;;OW)";
            if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out nint sd, out _)) return false;
            try { return NativeMethods.SetKernelObjectSecurity(NativeMethods.GetCurrentProcess(), NativeMethods.DACL_SECURITY_INFORMATION, sd); }
            finally { NativeMethods.LocalFree(sd); }
        });

        // 5. Threads have their own DACLs (taken from the token's default DACL). Without this, a same-user
        //    program could open one of our THREADS and hijack it (SetThreadContext / APC injection) even
        //    though the process handle is locked down. Restrict new threads (token default DACL) and every
        //    thread that already exists.
        Try("Restrict thread access (default + existing threads)", RestrictThreads);
    }

    // Threads: user/owner get only SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION; SYSTEM gets full access.
    private static string ThreadSddl(string sid) => $"D:P(A;;GA;;;SY)(A;;0x100800;;;{sid})(A;;0x100800;;;OW)";

    private static bool RestrictThreads()
    {
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptorW(ThreadSddl(sid), 1, out nint sd, out _)) return false;
        try
        {
            if (!NativeMethods.GetSecurityDescriptorDacl(sd, out _, out nint dacl, out _)) return false;
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TOKEN_ADJUST_DEFAULT | NativeMethods.TOKEN_QUERY, out nint token)) return false;
            try
            {
                if (!NativeMethods.SetTokenInformation(token, NativeMethods.TokenDefaultDacl, ref dacl, (uint)nint.Size)) return false;
            }
            finally { NativeMethods.CloseHandle(token); }

            bool all = true;
            foreach (ProcessThread t in Process.GetCurrentProcess().Threads)
            {
                nint h = NativeMethods.OpenThread(NativeMethods.THREAD_WRITE_DAC | NativeMethods.THREAD_READ_CONTROL, false, (uint)t.Id);
                if (h == 0) { all = false; continue; }
                try { all &= NativeMethods.SetKernelObjectSecurity(h, NativeMethods.DACL_SECURITY_INFORMATION, sd); }
                finally { NativeMethods.CloseHandle(h); }
            }
            return all;
        }
        finally { NativeMethods.LocalFree(sd); }
    }

    /// <summary>
    /// Security descriptor for the secure desktop: SYSTEM and the current user only (as the normal default),
    /// passed explicitly so it doesn't inherit our restricted token default DACL, which would leave the
    /// desktop unusable. The caller frees it with LocalFree.
    /// </summary>
    public static nint DesktopSecurityDescriptor()
    {
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        return NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;GA;;;SY)(A;;GA;;;{sid})", 1, out nint sd, out _) ? sd : 0;
    }

    public static bool DebuggerAttached()
    {
        if (Debugger.IsAttached || NativeMethods.IsDebuggerPresent()) return true;
        return NativeMethods.CheckRemoteDebuggerPresent(NativeMethods.GetCurrentProcess(), out bool remote) && remote;
    }

    private static void Try(string what, Func<bool> f)
    {
        try
        {
            if (f()) Applied.Add(what);
            else Failed.Add($"{what} (error {Marshal.GetLastPInvokeError()})");
        }
        catch (Exception e) { Failed.Add($"{what} ({e.GetType().Name})"); }
    }
}
