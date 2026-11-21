using System.Security.Cryptography;
using SecureVault.Core;

namespace SecureVault.App.Native;

/// <summary>
/// Binds a secret to this PC's TPM through the CNG "Microsoft Platform Crypto Provider".
/// The RSA-2048 private key is created inside the TPM and can't be exported. RSA-OAEP decryption
/// is deterministic in its output (the randomness is only in encryption), so unlocking gives the
/// same secret every time. That's verified on enrollment.
/// Blob format: [padding id: 1 = OAEP-SHA256, 2 = OAEP-SHA1] [RSA ciphertext].
/// </summary>
public sealed class TpmProtector : IDeviceKeyProtector
{
    private static readonly CngProvider Platform = new("Microsoft Platform Crypto Provider");

    public static bool IsAvailable(out string reason)
    {
        try
        {
            CngKey.Exists("SecureVault-probe-does-not-exist", Platform);
            reason = "";
            return true;
        }
        catch (CryptographicException e)
        {
            reason = e.Message;
            return false;
        }
    }

    public byte[] CreateKeyAndProtect(string keyName, ReadOnlySpan<byte> secret)
    {
        if (CngKey.Exists(keyName, Platform)) throw new InvalidOperationException("A TPM key with that name already exists.");
        var p = new CngKeyCreationParameters
        {
            Provider = Platform,
            KeyUsage = CngKeyUsages.Decryption,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
        };
        p.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        using var key = CngKey.Create(CngAlgorithm.Rsa, keyName, p);
        try
        {
            using var rsa = new RSACng(key);
            byte[] blob = Encrypt(rsa, secret);
            // Enrollment check: decrypt twice and make sure we get the same secret back both times.
            for (int i = 0; i < 2; i++)
            {
                byte[]? back = TryUnprotect(keyName, blob);
                bool ok = back is not null && CryptographicOperations.FixedTimeEquals(back, secret);
                if (back is not null) VaultCrypto.Wipe(back);
                if (!ok) throw new CryptographicException("TPM round-trip check failed; the TPM factor can't be used on this PC.");
            }
            return blob;
        }
        catch
        {
            try { key.Delete(); } catch { /* best effort */ }
            throw;
        }
    }

    private static byte[] Encrypt(RSACng rsa, ReadOnlySpan<byte> secret)
    {
        byte[] input = secret.ToArray();
        try
        {
            try { return [1, .. rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA256)]; }
            catch (CryptographicException) { return [2, .. rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA1)]; }
        }
        finally { VaultCrypto.Wipe(input); }
    }

    public byte[]? TryUnprotect(string keyName, ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 2 || !CngKey.Exists(keyName, Platform)) return null;
        var pad = blob[0] switch { 1 => RSAEncryptionPadding.OaepSHA256, 2 => RSAEncryptionPadding.OaepSHA1, _ => null };
        if (pad is null) return null;
        using var key = CngKey.Open(keyName, Platform);
        using var rsa = new RSACng(key);
        byte[] plain = rsa.Decrypt(blob[1..].ToArray(), pad);
        byte[] pinned = VaultCrypto.AllocSecret(plain.Length);
        plain.CopyTo(pinned, 0);
        VaultCrypto.Wipe(plain);
        return pinned;
    }

    public void DeleteKey(string keyName)
    {
        if (!CngKey.Exists(keyName, Platform)) return;
        using var key = CngKey.Open(keyName, Platform);
        key.Delete();
    }
}
