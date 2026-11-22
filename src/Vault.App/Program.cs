using System.Collections;
using System.Diagnostics;
using System.Windows;
using SecureVault.App.Native;
using SecureVault.App.Windows;

namespace SecureVault.App;

public static class Program
{
    private const string CleanMarker = "SECUREVAULT_CLEAN_ENV";

    /// <summary>
    /// Environment variables that let other code run inside a .NET process, or attach to it, before or
    /// after Main. A user-level program could set any of these in HKCU\Environment.
    /// </summary>
    private static bool IsDangerous(string name)
    {
        string n = name.ToUpperInvariant();
        return n.StartsWith("DOTNET_", StringComparison.Ordinal) || n.StartsWith("COREHOST_", StringComparison.Ordinal)
            || n.StartsWith("CORECLR_", StringComparison.Ordinal) || n.StartsWith("COR_", StringComparison.Ordinal)
            || n.StartsWith("COMPLUS_", StringComparison.Ordinal) || n.StartsWith("MICROSOFT_DIAGNOSTICS", StringComparison.Ordinal)
            || n == "APPDATA_OVERRIDE";
    }

    [STAThread]
    public static int Main(string[] args)
    {
        // 0. Browser native-messaging helper mode (started by Chrome/Edge with the extension origin as the first
        //    argument). Its stdin/stdout belong to the browser, so it can't relaunch. It refuses to relay
        //    anything if injection variables are set, holds no keys, and is hardened like the main app.
        if (Browser.NativeHost.IsHostInvocation(args))
        {
            Hardening.ApplyEarly();
            return Browser.NativeHost.Run(args, Browser.NativeHost.IsInjectionVariable);
        }

        // 1. Clean environment. Relaunch ourselves with every runtime-injection variable (startup hooks,
        //    profilers, DOTNET_ROOT, ...) removed, and with diagnostics turned off: no debugger attach, no
        //    profiler, no diagnostic IPC pipe (which would let a same-user tool dump our memory). The first
        //    process only relaunches; it never touches secrets.
        if (Environment.GetEnvironmentVariable(CleanMarker) != "1" || Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") != "0")
            return Relaunch(args);
        foreach (DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            string k = (string)e.Key;
            if (IsDangerous(k) && k != "DOTNET_EnableDiagnostics")
            {
                MessageBox.Show($"Refusing to start: environment variable {k} is set, which could inject code into SecureVault.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Stop);
                return 2;
            }
        }

        // 2. Single instance. Created before hardening, because the restricted default DACL would stop a
        //    second instance from even opening the mutex.
        Mutex single;
        bool first;
        try { single = new Mutex(true, @"Local\SecureVault-SingleInstance", out first); }
        catch (UnauthorizedAccessException) { first = false; single = null!; }
        bool selfTest = args.Contains("--selftest");
        if (!first && !selfTest)
        {
            MessageBox.Show("SecureVault is already running.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Information);
            return 1;
        }

        // 3. Harden the process before anything sensitive happens.
        Hardening.ApplyEarly();

        // The self-test may run while the real app is open; it then skips only the browser-bridge part.
        if (selfTest) return SelfTest.Run(appAlreadyRunning: !first);

        var app = new App();
        app.InitializeComponent();
        app.DispatcherUnhandledException += (_, e) =>
        {
            // Never write exception details (which may contain data) to disk; show a generic message and lock.
            e.Handled = true;
            (app.MainWindow as MainWindow)?.Lock("An unexpected error occurred; the vault was locked.");
            MessageBox.Show("Something went wrong: " + e.Exception.GetType().Name + ". The vault has been locked.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Error);
        };
        app.Exit += (_, _) => SecureClipboard.ClearIfOurs();
        int rc = app.Run(new MainWindow());
        GC.KeepAlive(single);
        return rc;
    }

    private static int Relaunch(string[] args)
    {
        if (Environment.GetEnvironmentVariable(CleanMarker) == "1") return 3; // loop guard
        var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (string k in psi.Environment.Keys.ToList())
            if (IsDangerous(k)) psi.Environment.Remove(k);
        psi.Environment["DOTNET_EnableDiagnostics"] = "0";
        psi.Environment[CleanMarker] = "1";
        using var p = Process.Start(psi)!;
        if (args.Contains("--selftest"))
        {
            p.WaitForExit();
            bool bridgeOk = SelfTest.RunBridgeChecksInLauncher(args);
            return p.ExitCode != 0 ? p.ExitCode : bridgeOk ? 0 : 1;
        }
        return 0;
    }
}
