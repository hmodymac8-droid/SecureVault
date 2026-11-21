using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SecureVault.Core;

namespace SecureVault.App;

/// <summary>Non-secret app preferences that must be known before unlock.</summary>
internal sealed class AppConfig
{
    public string? LastVaultPath { get; set; }
    public bool UseSecureDesktop { get; set; } = true;

    public static string Dir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureVault");
    private static string FilePath => Path.Combine(Dir, "config.json");
    public static string DefaultVaultPath => Path.Combine(Dir, "vault.pmv");

    public static AppConfig Load()
    {
        try { return JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(FilePath)) ?? new(); }
        catch { return new(); }
    }

    public void Save()
    {
        EnsurePrivateDir(Dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
    }

    /// <summary>Restrict a folder to the current user and SYSTEM only (no inherited ACEs).</summary>
    public static void EnsurePrivateDir(string dir)
    {
        var di = Directory.CreateDirectory(dir);
        try
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            di.SetAccessControl(sec);
        }
        catch { /* e.g. on a FAT32 USB drive: no ACLs; that's fine */ }
    }
}

/// <summary>
/// Anti-rollback. Remembers the highest save counter seen for each vault, DPAPI-protected (CurrentUser)
/// and in %LOCALAPPDATA%/SecureVault (a copied or restored vault file elsewhere is still checked against it). If someone swaps in an older copy (for example one from before a
/// password change), the user is warned. Malware running as the user could reset this file; that's
/// outside what it defends against.
/// </summary>
internal static class RollbackGuard
{
    private static readonly byte[] Entropy = "SecureVault/rollback/v1"u8.ToArray();
    private static string FilePath => Path.Combine(AppConfig.Dir, "rollback.dat");

    private static Dictionary<string, long> Load()
    {
        try
        {
            byte[] enc = File.ReadAllBytes(FilePath);
            byte[] plain = ProtectedData.Unprotect(enc, Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<Dictionary<string, long>>(plain) ?? [];
        }
        catch { return []; }
    }

    public enum Status { Ok, Older, NeverSeenHere }

    /// <summary>
    /// Older: the file is behind the highest version seen on this PC (possible rollback).
    /// NeverSeenHere: no record for a vault that has already been saved before. It could be a new PC, a deleted
    /// or corrupted record, or a rollback the guard can't detect, so the user is told rather than silently trusted.
    /// </summary>
    public static (Status Status, long Seen) Check(VaultHeader h)
    {
        var map = Load();
        if (!map.TryGetValue(h.VaultId, out long seen)) return (h.Counter > 1 ? Status.NeverSeenHere : Status.Ok, 0);
        return (h.Counter < seen ? Status.Older : Status.Ok, seen);
    }

    public static void Record(VaultHeader h)
    {
        var map = Load();
        if (map.TryGetValue(h.VaultId, out long seen) && seen >= h.Counter) return;
        map[h.VaultId] = h.Counter;
        AppConfig.EnsurePrivateDir(AppConfig.Dir);
        byte[] enc = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(map), Entropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(FilePath, enc);
    }
}
