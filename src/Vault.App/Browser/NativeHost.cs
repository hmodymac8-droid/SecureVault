using System.Collections;
using System.IO;
using System.IO.Pipes;
using SecureVault.Core;

namespace SecureVault.App.Browser;

/// <summary>
/// "Native messaging host" mode. Chrome or Edge starts SecureVault.exe with the extension's origin as the
/// first argument and talks over stdin/stdout. This helper holds no keys: it only relays each message to
/// the unlocked SecureVault window over the local pipe, which re-checks everything.
/// </summary>
internal static class NativeHost
{
    public static bool IsHostInvocation(string[] args) => args.Length > 0 && args[0].StartsWith("chrome-extension://", StringComparison.Ordinal);

    /// <summary>
    /// The helper inherits the browser's environment and can't relaunch itself, so it refuses to work if a
    /// variable that can load foreign code or write memory dumps is set. Harmless ones (telemetry opt-outs,
    /// for example) are fine. Startup hooks are already disabled by a runtime switch; this is defence in depth.
    /// </summary>
    public static bool IsInjectionVariable(string name)
    {
        string n = name.ToUpperInvariant();
        string[] exact = ["DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "CORECLR_ENABLE_PROFILING",
                          "COR_ENABLE_PROFILING", "DOTNET_DBGENABLEMINIDUMP", "COMPLUS_DBGENABLEMINIDUMP", "DOTNET_ENABLEDIAGNOSTICS_PROFILER"];
        return exact.Contains(n)
            || n.StartsWith("CORECLR_PROFILER", StringComparison.Ordinal) || n.StartsWith("COR_PROFILER", StringComparison.Ordinal)
            || n.StartsWith("DOTNET_PROFILER", StringComparison.Ordinal) || n.StartsWith("DOTNET_ROOT", StringComparison.Ordinal)
            || n.StartsWith("DOTNET_DBGMINIDUMP", StringComparison.Ordinal) || n.StartsWith("COMPLUS_DBGMINIDUMP", StringComparison.Ordinal);
    }

    public static int Run(string[] args, Func<string, bool> isDangerousEnv)
    {
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();

        string? refusal = null;
        if (args[0] != BrowserIds.ExtensionOrigin) refusal = "wrong_extension";
        foreach (DictionaryEntry e in Environment.GetEnvironmentVariables())
            if (isDangerousEnv((string)e.Key)) refusal = "unsafe_environment"; // code-injection variables: never relay secrets

        try
        {
            while (true)
            {
                byte[]? req = BrowserIds.ReadFrameAsync(stdin, BrowserProtocol.MaxRequestBytes, CancellationToken.None).GetAwaiter().GetResult();
                if (req is null) return 0; // browser closed the channel
                byte[] resp;
                try { resp = refusal is null ? Relay(req) : Json("{\"error\":\"" + refusal + "\"}"); }
                finally { VaultCrypto.Wipe(req); }
                try { BrowserIds.WriteFrameAsync(stdout, resp, CancellationToken.None).GetAwaiter().GetResult(); }
                finally { VaultCrypto.Wipe(resp); }
            }
        }
        catch (Exception) { return 1; }
    }

    private static byte[] Relay(byte[] req)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", BrowserIds.PipeName, PipeDirection.InOut, PipeOptions.CurrentUserOnly);
            pipe.Connect(1500);
            BrowserIds.WriteFrameAsync(pipe, req, CancellationToken.None).GetAwaiter().GetResult();
            return BrowserIds.ReadFrameAsync(pipe, BrowserIds.MaxResponseBytes, CancellationToken.None).GetAwaiter().GetResult()
                   ?? Json("{\"error\":\"not_running\"}");
        }
        catch (TimeoutException) { return Json("{\"error\":\"not_running\"}"); }
        catch (IOException) { return Json("{\"error\":\"not_running\"}"); }
        catch (UnauthorizedAccessException) { return Json("{\"error\":\"not_running\"}"); }
    }

    private static byte[] Json(string s) => System.Text.Encoding.UTF8.GetBytes(s);
}
