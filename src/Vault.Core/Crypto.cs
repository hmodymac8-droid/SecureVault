using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace SecureVault.Core;

/// <summary>
/// Argon2id cost parameters, stored in the vault header.
/// Parallelism is always 1: libsodium's Argon2 implementation supports only a single lane.
/// </summary>
public sealed record KdfParams(int MemoryKiB, int Passes, int Parallelism = 1)
{
    internal const int MaxMemoryKiB = 2 * 1024 * 1024; // 2 GiB: refuse absurd headers (this runs before any authentication)
    internal const int MaxPasses = 16;

    /// <summary>Starting point for calibration. Calibration only ever goes up from here.</summary>
    public static readonly KdfParams Default = new(512 * 1024, 3);
}

/// <summary>
/// The minimum KDF strength accepted when opening a vault, so a tampered or substituted header
/// can't downgrade it. Only the test project may use the weak policy.
/// </summary>
public sealed record KdfPolicy(int MinMemoryKiB, int MinPasses)
{
    public static readonly KdfPolicy Production = new(256 * 1024, 3);
    internal static readonly KdfPolicy Testing = new(8 * 1024, 1);

    public void Enforce(KdfParams p)
    {
        if (p.Parallelism != 1)
            throw new VaultFormatException("Unsupported Argon2 parallelism (libsodium supports only 1).");
        if (p.MemoryKiB < MinMemoryKiB || p.Passes < MinPasses)
            throw new VaultFormatException("Vault key-derivation parameters are weaker than allowed.");
        if (p.MemoryKiB > KdfParams.MaxMemoryKiB || p.Passes > KdfParams.MaxPasses)
            throw new VaultFormatException("Vault key-derivation parameters are out of range.");
    }
}

/// <summary>Low-level primitives. All symmetric crypto goes through libsodium (NSec).</summary>
public static class VaultCrypto
{
    public const int KeySize = 32;
    public const int SaltSize = 16;
    public const int NonceSize = 24;
    public const int TagSize = 16;
    public const int CommitSize = 32;

    internal static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;
    // KeyCreationParameters is a ref struct, so it's built inline at each use.
    private static KeyCreationParameters NoExport => new() { ExportPolicy = KeyExportPolicies.None };
    private static KeyCreationParameters Exportable => new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

    /// <summary>Pinned buffer: the GC never moves it, so no stray copies of the secret are left in RAM.</summary>
    public static byte[] AllocSecret(int length) => GC.AllocateArray<byte>(length, pinned: true);
    public static char[] AllocSecretChars(int length) => GC.AllocateArray<char>(length, pinned: true);

    public static void Wipe(Span<byte> s) => CryptographicOperations.ZeroMemory(s);
    public static void Wipe(Span<char> s) => CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(s));

    public static byte[] RandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static void DerivePasswordKey(ReadOnlySpan<byte> passwordUtf8, ReadOnlySpan<byte> salt, KdfParams p, Span<byte> output)
    {
        if (salt.Length != SaltSize) throw new ArgumentException("Bad salt size.", nameof(salt));
        var alg = PasswordBasedKeyDerivationAlgorithm.Argon2id(new Argon2Parameters
        {
            DegreeOfParallelism = p.Parallelism,
            MemorySize = p.MemoryKiB,
            NumberOfPasses = p.Passes,
        });
        alg.DeriveBytes(passwordUtf8, salt, output);
    }

    public static void Hkdf(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, Span<byte> output)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, Encoding.UTF8.GetBytes(info));

    /// <summary>
    /// Key commitment. XChaCha20-Poly1305 isn't key-committing, so we store HMAC(key, context)
    /// and check it in constant time before trying to decrypt.
    /// </summary>
    public static byte[] Commit(ReadOnlySpan<byte> key, string context)
        => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("SVLT/v1/commit|" + context));

    public static bool VerifyCommit(ReadOnlySpan<byte> key, string context, ReadOnlySpan<byte> expected)
    {
        byte[] actual = Commit(key, context);
        try { return CryptographicOperations.FixedTimeEquals(actual, expected); }
        finally { Wipe(actual); }
    }

    public static byte[] Seal(ReadOnlySpan<byte> rawKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
    {
        using var key = Key.Import(Aead, rawKey, KeyBlobFormat.RawSymmetricKey, NoExport);
        return Aead.Encrypt(key, nonce, aad, plaintext);
    }

    public static bool TryOpen(ReadOnlySpan<byte> rawKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        using var key = Key.Import(Aead, rawKey, KeyBlobFormat.RawSymmetricKey, NoExport);
        return Aead.Decrypt(key, nonce, aad, ciphertext, plaintext);
    }

    internal static byte[] Seal(Key key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
        => Aead.Encrypt(key, nonce, aad, plaintext);

    internal static bool TryOpen(Key key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        => Aead.Decrypt(key, nonce, aad, ciphertext, plaintext);

    /// <summary>Data key, kept in libsodium guarded memory. Exportable only so new key slots can wrap it.</summary>
    internal static Key ImportDataKey(ReadOnlySpan<byte> raw) => Key.Import(Aead, raw, KeyBlobFormat.RawSymmetricKey, Exportable);

    internal static Key CreateEphemeralKey() => new(Aead, NoExport);

    internal static byte[] ExportDataKey(Key key)
    {
        byte[] buf = AllocSecret(KeySize);
        if (!key.TryExport(KeyBlobFormat.RawSymmetricKey, buf, out int written) || written != KeySize)
        {
            Wipe(buf);
            throw new CryptographicException("Could not export data key.");
        }
        return buf;
    }

    /// <summary>
    /// Raise Argon2id passes until one derivation takes about <paramref name="target"/>.
    /// Never goes below <see cref="KdfParams.Default"/> or the production floor.
    /// </summary>
    public static KdfParams Calibrate(TimeSpan target)
    {
        byte[] pwd = AllocSecret(16), salt = RandomBytes(SaltSize), outKey = AllocSecret(KeySize);
        try
        {
            int mem = KdfParams.Default.MemoryKiB;
            int passes = Math.Max(KdfParams.Default.Passes, KdfPolicy.Production.MinPasses);
            TimeSpan t;
            try { t = Time(mem, passes); }
            catch (Exception e) when (e is OutOfMemoryException or InvalidOperationException)
            {
                mem = KdfPolicy.Production.MinMemoryKiB;
                t = Time(mem, passes);
            }
            while (t < target && passes < 12)
            {
                passes++;
                t = Time(mem, passes);
            }
            return new KdfParams(mem, passes);
        }
        finally { Wipe(pwd); Wipe(outKey); }

        TimeSpan Time(int m, int p)
        {
            var sw = Stopwatch.StartNew();
            DerivePasswordKey(pwd, salt, new KdfParams(m, p), outKey);
            return sw.Elapsed;
        }
    }
}

public class VaultFormatException(string message) : Exception(message);

/// <summary>Wrong password, keyfile, recovery key or device, or the file was modified. Deliberately vague.</summary>
public sealed class VaultAuthException() : Exception("Unlock failed: wrong master password, keyfile or recovery key, or this vault was modified.");
