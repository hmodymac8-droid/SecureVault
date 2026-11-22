using System.Text;
using SecureVault.Core;

namespace SecureVault.Tests;

/// <summary>In-memory stand-in for the TPM, so slot logic can be tested on any machine.</summary>
internal sealed class FakeDevice : IDeviceKeyProtector
{
    private readonly Dictionary<string, byte[]> _keys = [];
    public int Count => _keys.Count;

    public byte[] CreateKeyAndProtect(string keyName, ReadOnlySpan<byte> secret)
    {
        var k = VaultCrypto.RandomBytes(32);
        _keys[keyName] = k;
        var nonce = VaultCrypto.RandomBytes(24);
        return [.. nonce, .. VaultCrypto.Seal(k, nonce, default, secret)];
    }

    public byte[]? TryUnprotect(string keyName, ReadOnlySpan<byte> blob)
    {
        if (!_keys.TryGetValue(keyName, out var k)) return null;
        var outp = VaultCrypto.AllocSecret(blob.Length - 24 - 16);
        return VaultCrypto.TryOpen(k, blob[..24], default, blob[24..], outp) ? outp : null;
    }

    public void DeleteKey(string keyName) => _keys.Remove(keyName);
}

public sealed class VaultTests : IDisposable
{
    private static readonly KdfParams Fast = new(8 * 1024, 1);
    private readonly string _dir = Directory.CreateTempSubdirectory("svlt-test-").FullName;
    private string VaultPath => Path.Combine(_dir, "vault.pmv");

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static byte[] Pw(string s) { var b = VaultCrypto.AllocSecret(Encoding.UTF8.GetByteCount(s)); Encoding.UTF8.GetBytes(s, b); return b; }
    private static UnlockRequest Req(string pw, byte[]? keyfile = null, IDeviceKeyProtector? dev = null) =>
        new() { PasswordUtf8 = Pw(pw), KeyfileHash = keyfile is null ? null : (byte[])keyfile.Clone(), Device = dev };

    private (VaultSession, string) NewVault(string pw = "correct horse battery staple", byte[]? keyfile = null, IDeviceKeyProtector? dev = null)
    {
        using var r = Req(pw, keyfile, dev);
        return VaultSession.Create(VaultPath, r, useTpm: dev is not null, Fast, KdfPolicy.Testing);
    }

    private VaultSession OpenWith(UnlockRequest r) { using (r) return VaultSession.Open(VaultPath, r, KdfPolicy.Testing); }

    private static void AddEntry(VaultSession s, string title, string password)
    {
        s.Data.Entries.Add(new VaultEntry
        {
            Title = title, Username = "me@example.com", Url = "https://example.com",
            Password = ProtectedText.FromChars(s.Protector, password),
            Notes = ProtectedText.FromChars(s.Protector, "line1\n\"quoted\" ü 🔑"),
        });
        s.Save();
    }

    [Fact]
    public void RoundTrip_Password()
    {
        var (s, _) = NewVault();
        AddEntry(s, "Bank", "p\"a\\ss\u0001wörd");
        s.Dispose();
        Assert.True(s.IsLocked);

        using var s2 = OpenWith(Req("correct horse battery staple"));
        var e = Assert.Single(s2.Data.Entries);
        Assert.Equal("Bank", e.Title);
        Assert.Equal("p\"a\\ss\u0001wörd", e.Password.RevealToString());
        Assert.Equal("line1\n\"quoted\" ü 🔑", e.Notes.RevealToString());
    }

    [Fact]
    public void FileContainsNoPlaintext()
    {
        var (s, _) = NewVault();
        AddEntry(s, "VerySecretTitle", "SuperSecretPassword123");
        s.Dispose();
        string raw = Encoding.Latin1.GetString(File.ReadAllBytes(VaultPath));
        Assert.DoesNotContain("VerySecretTitle", raw);
        Assert.DoesNotContain("SuperSecretPassword123", raw);
        Assert.DoesNotContain("example.com", raw);
    }

    [Fact]
    public void WrongPassword_Fails()
    {
        NewVault().Item1.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("wrong password here")));
    }

    [Fact]
    public void Keyfile_RequiredAndChecked()
    {
        var kf = VaultCrypto.RandomBytes(32);
        NewVault(keyfile: kf).Item1.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("correct horse battery staple")));
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("correct horse battery staple", VaultCrypto.RandomBytes(32))));
        OpenWith(Req("correct horse battery staple", kf)).Dispose();
    }

    [Fact]
    public void KeyfileOnDisk_CreateAndHash()
    {
        string p = Path.Combine(_dir, "my.key");
        Keyfile.Create(p);
        Assert.Throws<IOException>(() => Keyfile.Create(p));
        Assert.Equal(Keyfile.Hash(p), Keyfile.Hash(p));
    }

    [Fact]
    public void Tpm_RequiresDevice_AndIsDeterministic()
    {
        var dev = new FakeDevice();
        NewVault(dev: dev).Item1.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("correct horse battery staple")));
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("correct horse battery staple", dev: new FakeDevice())));
        for (int i = 0; i < 3; i++) OpenWith(Req("correct horse battery staple", dev: dev)).Dispose();
    }

    [Fact]
    public void RecoveryKey_Unlocks_EvenWhenTpmLost()
    {
        var dev = new FakeDevice();
        var (s, recovery) = NewVault(dev: dev);
        AddEntry(s, "A", "x");
        s.Dispose();

        var secret = RecoveryKey.TryParse(recovery.ToLowerInvariant().Replace("-", " "));
        Assert.NotNull(secret);
        using var s2 = OpenWith(new UnlockRequest { RecoveryKey = secret });
        Assert.Single(s2.Data.Entries);

        var bad = RecoveryKey.Generate().Secret;
        Assert.Throws<VaultAuthException>(() => OpenWith(new UnlockRequest { RecoveryKey = bad }));
    }

    [Fact]
    public void RecoveryKey_ChecksumCatchesTypos()
    {
        var (secret, display) = RecoveryKey.Generate();
        Assert.Equal(49, display.Length);
        Assert.Equal(secret, RecoveryKey.TryParse(display));
        char c = display[0] == 'A' ? 'B' : 'A';
        Assert.Null(RecoveryKey.TryParse(c + display[1..]));
        Assert.Null(RecoveryKey.TryParse(display[..^1]));
    }

    private const string P = "correct horse battery staple";

    [Fact]
    public void ChangePassword_OldFails_NewWorks_NewRecoveryIssued()
    {
        var (s, oldRecovery) = NewVault();
        AddEntry(s, "A", "x");
        var r = s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), null, null);
        Assert.Empty(r.DroppedOtherPcTpmSlots);
        Assert.True(s.Data.Settings.RecoveryKitPending);
        s.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req(P)));
        OpenWith(Req("a brand new long passphrase")).Dispose();
        // The data key rotated, so the old recovery key (which wrapped the OLD data key) is gone too.
        Assert.Throws<VaultAuthException>(() => OpenWith(new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(oldRecovery) }));
        OpenWith(new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(r.RecoveryKey) }).Dispose();
    }

    [Fact]
    public void Rotation_OldBackupKeyCannotDecryptNewVersions()
    {
        var (s, _) = NewVault();
        AddEntry(s, "A", "x");
        byte[] oldFile = File.ReadAllBytes(VaultPath);
        s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), null, null);
        AddEntry(s, "Secret added later", "y");
        s.Dispose();

        // An attacker who knows the OLD password and has an OLD copy gets the OLD data key...
        using var old = VaultSession.Open(VaultPath, oldFile, Req(P), KdfPolicy.Testing);
        var oldHeader = old.Header;
        var newHeader = VaultFile.ReadHeader(VaultPath, KdfPolicy.Testing);
        // ...which differs from the current one, so new versions stay sealed.
        Assert.NotEqual(oldHeader.DataKeyCommit, newHeader.DataKeyCommit);
        byte[] oldKey = VaultCrypto.ExportDataKey(GetKey(old));
        var parsed = VaultFile.Parse(File.ReadAllBytes(VaultPath), KdfPolicy.Testing);
        var pt = new byte[parsed.Ciphertext.Length - 16];
        Assert.False(VaultCrypto.TryOpen(oldKey, parsed.Nonce, parsed.Aad, parsed.Ciphertext, pt));
    }

    private static NSec.Cryptography.Key GetKey(VaultSession s) =>
        (NSec.Cryptography.Key)typeof(VaultSession).GetField("_dataKey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(s)!;

    [Fact]
    public void ChangePassword_KeepsTpmSlotOnThisDevice()
    {
        var dev = new FakeDevice();
        var (s, _) = NewVault(dev: dev);
        s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), null, dev);
        s.Dispose();
        Assert.Equal(1, dev.Count); // old TPM key deleted, new one created
        OpenWith(Req("a brand new long passphrase", dev: dev)).Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("a brand new long passphrase")));
    }

    [Fact]
    public void Rekey_RefusesMissingOrWrongKeyfile_NoDowngrade()
    {
        var kf = VaultCrypto.RandomBytes(32);
        var (s, _) = NewVault(keyfile: kf);
        long before = s.Header.Counter;
        Assert.Throws<InvalidOperationException>(() => s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), null, null));
        Assert.Throws<InvalidOperationException>(() => s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), VaultCrypto.RandomBytes(32), null));
        Assert.Equal(before, s.Header.Counter); // nothing saved
        s.ChangePassword(Pw(P), Pw("a brand new long passphrase"), kf, null);
        s.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req("a brand new long passphrase"))); // still needs the keyfile
        OpenWith(Req("a brand new long passphrase", kf)).Dispose();
    }

    [Fact]
    public void Rekey_TpmErrorAborts_OtherPcTpmIsDroppedAndReported()
    {
        var dev = new FakeDevice();
        var (s, _) = NewVault(dev: dev);
        s.AddPasswordSlot(Pw(P), null, null, "Password");
        Assert.Throws<InvalidOperationException>(() => s.ChangePassword(Pw(P), Pw("new long passphrase!!"), null, new ThrowingDevice()));
        var r = s.ChangePassword(Pw(P), Pw("new long passphrase!!"), null, new FakeDevice()); // a different PC
        Assert.Single(r.DroppedOtherPcTpmSlots);
        Assert.DoesNotContain(s.Header.Slots, x => x.UsesTpm);
        s.Dispose();
    }

    private sealed class ThrowingDevice : IDeviceKeyProtector
    {
        public byte[] CreateKeyAndProtect(string keyName, ReadOnlySpan<byte> secret) => throw new InvalidOperationException("TPM busy");
        public byte[]? TryUnprotect(string keyName, ReadOnlySpan<byte> blob) => throw new InvalidOperationException("TPM lockout");
        public void DeleteKey(string keyName) { }
    }

    [Fact]
    public void Slots_AddAndRemove_RemovalRotates()
    {
        var (s, _) = NewVault();
        var kf = VaultCrypto.RandomBytes(32);
        var slot = s.AddPasswordSlot(Pw(P), kf, null, "USB keyfile");
        s.Dispose();
        OpenWith(Req(P, kf)).Dispose();
        OpenWith(Req(P)).Dispose();

        using var s2 = OpenWith(Req(P));
        var commitBefore = s2.Header.DataKeyCommit;
        var plain = s2.Header.Slots.First(x => x.Kind == SlotKind.Password && !x.Keyfile);
        s2.RemoveSlot(plain.Id, Pw(P), kf, null);
        Assert.NotEqual(commitBefore, s2.Header.DataKeyCommit);
        var kfSlot = s2.Header.Slots.Single(x => x.Kind == SlotKind.Password);
        Assert.Throws<InvalidOperationException>(() => s2.RemoveSlot(kfSlot.Id, Pw(P), kf, null)); // last password slot
        var rec = s2.Header.Slots.Single(x => x.Kind == SlotKind.Recovery);
        Assert.Throws<InvalidOperationException>(() => s2.RemoveSlot(rec.Id, Pw(P), kf, null));
        s2.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(Req(P)));
        OpenWith(Req(P, kf)).Dispose();
        _ = slot;
    }

    [Fact]
    public void ReplaceRecovery_InvalidatesOld()
    {
        var (s, oldKey) = NewVault();
        string newKey = s.ReplaceRecoveryKey(Pw(P), null, null).RecoveryKey;
        s.Dispose();
        Assert.Throws<VaultAuthException>(() => OpenWith(new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(oldKey) }));
        OpenWith(new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(newKey) }).Dispose();
    }

    [Fact]
    public void UnconfirmedKit_IsPendingAcrossReopen_AndCanBeReissued()
    {
        var (s, _) = NewVault();
        Assert.True(s.Data.Settings.RecoveryKitPending);
        s.Dispose();
        using var s2 = OpenWith(Req(P));
        Assert.True(s2.Data.Settings.RecoveryKitPending);
        string k = s2.ReissueUnconfirmedRecoveryKey();
        s2.ConfirmRecoveryKit();
        Assert.Throws<InvalidOperationException>(() => s2.ReissueUnconfirmedRecoveryKey());
        s2.Dispose();
        using var s3 = OpenWith(new UnlockRequest { RecoveryKey = RecoveryKey.TryParse(k) });
        Assert.False(s3.Data.Settings.RecoveryKitPending);
    }

    [Fact]
    public void PurgeBackups_DeletesThem()
    {
        var (s, _) = NewVault();
        s.Save(); s.Save();
        Assert.True(s.PurgeBackups() >= 2);
        Assert.Empty(Directory.GetFiles(VaultFile.BackupDirectory(VaultPath)));
        s.Dispose();
    }

    [Fact]
    public void Counter_IncreasesEverySave()
    {
        var (s, _) = NewVault();
        long c0 = s.Header.Counter;
        s.Save(); s.Save();
        Assert.Equal(c0 + 2, s.Header.Counter);
        s.Dispose();
        Assert.Equal(c0 + 2, VaultFile.ReadHeader(VaultPath, KdfPolicy.Testing).Counter);
    }

    [Fact]
    public void Backups_RotateAndAreOpenable()
    {
        var (s, _) = NewVault();
        s.Data.Settings.MaxBackups = 3;
        for (int i = 0; i < 6; i++) s.Save();
        s.Dispose();
        var backups = Directory.GetFiles(VaultFile.BackupDirectory(VaultPath));
        Assert.Equal(3, backups.Length);
        using var r = Req("correct horse battery staple");
        VaultSession.Open(backups.Max()!, r, KdfPolicy.Testing).Dispose();
    }

    [Fact]
    public void ProductionPolicy_RejectsWeakKdf()
    {
        NewVault().Item1.Dispose();
        using var r = Req("correct horse battery staple");
        var ex = Assert.Throws<VaultFormatException>(() => VaultSession.Open(VaultPath, r));
        Assert.Contains("weaker", ex.Message);
    }

    [Fact]
    public void EveryHeaderByte_AndSampledBodyBytes_AreTamperEvident()
    {
        var (s, _) = NewVault();
        AddEntry(s, "A", "x");
        s.Dispose();
        byte[] orig = File.ReadAllBytes(VaultPath);
        int headerEnd = 10 + BitConverter.ToInt32(orig, 6) + 24;
        var positions = Enumerable.Range(0, headerEnd).Concat(Enumerable.Range(headerEnd, orig.Length - headerEnd).Where(i => i % 61 == 0 || i >= orig.Length - 16));
        foreach (int i in positions)
        {
            byte[] f = (byte[])orig.Clone();
            f[i] ^= 0x01;
            using var r = Req("correct horse battery staple");
            var ex = Record.Exception(() => VaultSession.Open(VaultPath, f, r, KdfPolicy.Testing).Dispose());
            Assert.True(ex is VaultAuthException or VaultFormatException, $"byte {i}: {ex?.GetType().Name ?? "opened!"}");
        }
    }

    [Fact]
    public void RandomMutations_NeverCrashOrOpen()
    {
        var (s, _) = NewVault();
        s.Dispose();
        byte[] orig = File.ReadAllBytes(VaultPath);
        var rng = new Random(1234);
        for (int n = 0; n < 300; n++)
        {
            byte[] f = (byte[])orig.Clone();
            switch (rng.Next(3))
            {
                case 0: for (int k = 0; k < 1 + rng.Next(8); k++) f[rng.Next(f.Length)] = (byte)rng.Next(256); break;
                case 1: f = f[..rng.Next(f.Length)]; break;
                default: { var extra = new byte[rng.Next(1, 64)]; rng.NextBytes(extra); f = [.. f, .. extra]; break; }
            }
            // A random overwrite can write the value a byte already had; an unchanged file must open, so skip it.
            if (f.AsSpan().SequenceEqual(orig)) continue;
            using var r = Req("correct horse battery staple");
            var ex = Record.Exception(() => VaultSession.Open(VaultPath, f, r, KdfPolicy.Testing).Dispose());
            Assert.True(ex is VaultAuthException or VaultFormatException, $"iter {n}: {ex?.ToString() ?? "opened!"}");
        }
    }

    [Fact]
    public void Create_RefusesToOverwrite()
    {
        NewVault().Item1.Dispose();
        Assert.Throws<IOException>(() => NewVault());
    }
}
