using System.Security.Cryptography;
using System.Text;

namespace SecureVault.Core;

/// <summary>
/// A device-bound protector, such as a TPM key that can't be exported. Decrypting the same blob
/// with the same key always returns the same bytes, so unlocking is deterministic. (A
/// signature-based scheme could add randomness and break this.)
/// </summary>
public interface IDeviceKeyProtector
{
    /// <summary>Create a new non-exportable key and return a round-trip-verified blob for <paramref name="secret"/>.</summary>
    byte[] CreateKeyAndProtect(string keyName, ReadOnlySpan<byte> secret);
    /// <summary>Returns the secret in a pinned buffer the caller must wipe, or null if the key isn't on this device.</summary>
    byte[]? TryUnprotect(string keyName, ReadOnlySpan<byte> blob);
    void DeleteKey(string keyName);
}

/// <summary>What the user supplied to unlock.</summary>
public sealed class UnlockRequest : IDisposable
{
    /// <summary>UTF-8 master password in a pinned buffer (wiped on Dispose).</summary>
    public byte[]? PasswordUtf8 { get; init; }
    /// <summary>SHA-256 of the keyfile, if one was given.</summary>
    public byte[]? KeyfileHash { get; init; }
    /// <summary>Decoded recovery key, if unlocking via the emergency kit.</summary>
    public byte[]? RecoveryKey { get; init; }
    public IDeviceKeyProtector? Device { get; init; }

    public void Dispose()
    {
        if (PasswordUtf8 is not null) VaultCrypto.Wipe(PasswordUtf8);
        if (KeyfileHash is not null) VaultCrypto.Wipe(KeyfileHash);
        if (RecoveryKey is not null) VaultCrypto.Wipe(RecoveryKey);
    }
}

public static class Keyfile
{
    public static byte[] Hash(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Keyfile not found.", path);
        if (info.Length is 0 or > 64L * 1024 * 1024) throw new InvalidDataException("A keyfile must be between 1 byte and 64 MiB.");
        using var fs = File.OpenRead(path);
        byte[] h = VaultCrypto.AllocSecret(32);
        SHA256.HashData(fs, h);
        return h;
    }

    /// <summary>Write 64 random bytes. Refuses to overwrite an existing file.</summary>
    public static void Create(string path)
    {
        byte[] data = VaultCrypto.AllocSecret(64);
        RandomNumberGenerator.Fill(data);
        try
        {
            using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            fs.Write(data);
            fs.Flush(true);
        }
        finally { VaultCrypto.Wipe(data); }
    }
}

/// <summary>
/// The emergency-kit recovery key: 160 random bits plus a 40-bit checksum, written as 40 Base32
/// characters in groups of four. That's enough entropy that no slow KDF is needed.
/// </summary>
public static class RecoveryKey
{
    public const int SecretSize = 20;
    private const int CheckSize = 5;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static (byte[] Secret, string Display) Generate()
    {
        byte[] secret = VaultCrypto.AllocSecret(SecretSize);
        RandomNumberGenerator.Fill(secret);
        return (secret, Format(secret));
    }

    internal static string Format(ReadOnlySpan<byte> secret)
    {
        Span<byte> all = stackalloc byte[SecretSize + CheckSize];
        secret.CopyTo(all);
        Span<byte> h = stackalloc byte[32];
        SHA256.HashData(secret, h);
        h[..CheckSize].CopyTo(all[SecretSize..]);
        var sb = new StringBuilder(49);
        int bits = 0, acc = 0, n = 0;
        foreach (byte b in all)
        {
            acc = (acc << 8) | b; bits += 8;
            while (bits >= 5)
            {
                if (n > 0 && n % 4 == 0) sb.Append('-');
                sb.Append(Alphabet[(acc >> (bits - 5)) & 31]);
                bits -= 5; n++;
            }
        }
        VaultCrypto.Wipe(all);
        return sb.ToString();
    }

    /// <summary>Parse user input (case, spaces and dashes don't matter). Returns null if it's malformed or the checksum fails.</summary>
    public static byte[]? TryParse(ReadOnlySpan<char> input)
    {
        Span<byte> all = stackalloc byte[SecretSize + CheckSize];
        int bits = 0, acc = 0, o = 0, chars = 0;
        foreach (char raw in input)
        {
            if (raw is ' ' or '-' or '\t') continue;
            char c = char.ToUpperInvariant(raw);
            // Common transcription slips
            c = c switch { '0' => 'O', '1' => 'I', '8' => 'B', _ => c };
            int v = Alphabet.IndexOf(c);
            if (v < 0) return null;
            chars++;
            if (chars > 40) return null;
            acc = (acc << 5) | v; bits += 5;
            if (bits >= 8) { all[o++] = (byte)(acc >> (bits - 8)); bits -= 8; }
        }
        if (chars != 40 || o != SecretSize + CheckSize) return null;
        Span<byte> h = stackalloc byte[32];
        SHA256.HashData(all[..SecretSize], h);
        if (!CryptographicOperations.FixedTimeEquals(h[..CheckSize], all[SecretSize..])) { VaultCrypto.Wipe(all); return null; }
        byte[] secret = VaultCrypto.AllocSecret(SecretSize);
        all[..SecretSize].CopyTo(secret);
        VaultCrypto.Wipe(all);
        return secret;
    }
}
