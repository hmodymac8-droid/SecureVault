using System.Text;
using SecureVault.App.Native;
using SecureVault.Core;
using Xunit.Abstractions;

namespace SecureVault.Tests;

/// <summary>
/// Runs against the REAL TPM of the machine running the tests. Checks that unlocking is deterministic:
/// the same blob decrypts to the same secret every time, and a vault bound to the TPM opens repeatedly.
/// It's a no-op on machines without a TPM (the output says so).
/// </summary>
public sealed class TpmTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("svlt-tpm-").FullName;
    private readonly List<string> _keys = [];
    private readonly TpmProtector _tpm = new();

    public void Dispose()
    {
        foreach (var k in _keys) try { _tpm.DeleteKey(k); } catch { }
        Directory.Delete(_dir, true);
    }

    [Fact]
    public void RealTpm_RoundTripIsDeterministic_AndVaultReopens()
    {
        if (!TpmProtector.IsAvailable(out string why)) { output.WriteLine("No TPM on this machine; skipped: " + why); return; }

        string name = "SecureVault-" + new string('a', 32) + "-" + Convert.ToHexStringLower(VaultCrypto.RandomBytes(8));
        _keys.Add(name);
        byte[] secret = VaultCrypto.RandomBytes(32);
        byte[] blob = _tpm.CreateKeyAndProtect(name, secret);
        output.WriteLine($"TPM blob: {blob.Length} bytes, padding id {blob[0]} (1 = OAEP-SHA256, 2 = OAEP-SHA1)");
        for (int i = 0; i < 5; i++) Assert.Equal(secret, _tpm.TryUnprotect(name, blob));
        _tpm.DeleteKey(name);
        Assert.Null(_tpm.TryUnprotect(name, blob)); // key gone → no unlock

        // A full vault bound to the TPM opens several times in a row.
        string path = Path.Combine(_dir, "v.pmv");
        byte[] Pw() => Encoding.UTF8.GetBytes("correct horse battery staple");
        VaultSession s;
        using (var r = new UnlockRequest { PasswordUtf8 = Pw(), Device = _tpm })
            (s, _) = VaultSession.Create(path, r, useTpm: true, new KdfParams(8 * 1024, 1), KdfPolicy.Testing);
        _keys.Add(s.Header.Slots.First(x => x.UsesTpm).TpmKeyName!);
        s.Dispose();
        for (int i = 0; i < 3; i++)
            using (var r = new UnlockRequest { PasswordUtf8 = Pw(), Device = _tpm })
                VaultSession.Open(path, r, KdfPolicy.Testing).Dispose();
        using (var r = new UnlockRequest { PasswordUtf8 = Pw() })
            Assert.Throws<VaultAuthException>(() => VaultSession.Open(path, r, KdfPolicy.Testing));
        output.WriteLine("TPM-bound vault reopened 3/3 times; without the TPM it refuses.");
    }
}
