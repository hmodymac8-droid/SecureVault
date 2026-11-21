using System.Buffers.Binary;
using NSec.Cryptography;

namespace SecureVault.Core;

/// <summary>An unlocked vault. Dispose (lock) wipes the keys and drops the decrypted data.</summary>
public sealed class VaultSession : IDisposable
{
    private Key? _dataKey;
    private TextProtector? _protector;
    private VaultData? _data;
    private readonly KdfPolicy _policy;

    public string Path { get; }
    public VaultHeader Header { get; private set; }
    public string UnlockedViaSlotId { get; }
    public bool IsLocked => _dataKey is null;

    public VaultData Data => _data ?? throw new ObjectDisposedException(nameof(VaultSession), "Vault is locked.");
    public TextProtector Protector => _protector ?? throw new ObjectDisposedException(nameof(VaultSession), "Vault is locked.");
    private Key DataKey => _dataKey ?? throw new ObjectDisposedException(nameof(VaultSession), "Vault is locked.");

    private VaultSession(string path, VaultHeader header, Key dataKey, TextProtector p, VaultData data, string slotId, KdfPolicy policy)
    {
        Path = path; Header = header; _dataKey = dataKey; _protector = p; _data = data; UnlockedViaSlotId = slotId; _policy = policy;
    }

    // ───────────────────────────── Create ─────────────────────────────

    /// <summary>
    /// Create a new vault with one password slot (optionally with a keyfile and/or TPM) and a mandatory
    /// recovery slot. Returns the session and the recovery key to show to the user once.
    /// </summary>
    public static (VaultSession Session, string RecoveryKey) Create(
        string path, UnlockRequest req, bool useTpm, KdfParams kdf, KdfPolicy? policy = null)
    {
        policy ??= KdfPolicy.Production;
        policy.Enforce(kdf);
        if (req.PasswordUtf8 is null) throw new ArgumentException("A password is required.");
        if (useTpm && req.Device is null) throw new ArgumentException("TPM requested but no device protector was supplied.");
        if (File.Exists(path)) throw new IOException("A vault already exists at that path.");

        byte[] dataKeyRaw = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        System.Security.Cryptography.RandomNumberGenerator.Fill(dataKeyRaw);
        string vaultId = Convert.ToHexStringLower(VaultCrypto.RandomBytes(16));
        var header = new VaultHeader
        {
            VaultId = vaultId,
            Counter = 0,
            Kdf = kdf,
            Salt = VaultCrypto.RandomBytes(VaultCrypto.SaltSize),
            DataKeyCommit = VaultCrypto.Commit(dataKeyRaw, $"data|{vaultId}"),
            Slots = [],
        };
        var protector = new TextProtector();
        Key? dataKey = null;
        try
        {
            header.Slots.Add(MakePasswordSlot(header, dataKeyRaw, req.PasswordUtf8, req.KeyfileHash, useTpm ? req.Device : null, "Master password"));
            var (recoverySlot, display) = MakeRecoverySlot(header, dataKeyRaw);
            header.Slots.Add(recoverySlot);
            dataKey = VaultCrypto.ImportDataKey(dataKeyRaw);
            var s = new VaultSession(path, header, dataKey, protector, new VaultData(), header.Slots[0].Id, policy);
            s.Data.Settings.RecoveryKitPending = true; // cleared when the user confirms the emergency kit
            s.Save();
            return (s, display);
        }
        catch
        {
            dataKey?.Dispose();
            protector.Dispose();
            throw;
        }
        finally { VaultCrypto.Wipe(dataKeyRaw); }
    }

    // ───────────────────────────── Open ─────────────────────────────

    public static VaultSession Open(string path, UnlockRequest req, KdfPolicy? policy = null)
        => Open(path, VaultFile.ReadAllBounded(path), req, policy ?? KdfPolicy.Production);

    internal static VaultSession Open(string path, byte[] file, UnlockRequest req, KdfPolicy policy)
    {
        var parsed = VaultFile.Parse(file, policy);
        var h = parsed.Header;
        byte[] dataKeyRaw = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        try
        {
            string slotId = UnwrapAny(h, req, dataKeyRaw) ?? throw new VaultAuthException();
            if (!VaultCrypto.VerifyCommit(dataKeyRaw, h.DataKeyContext, h.DataKeyCommit)) throw new VaultAuthException();

            int ptLen = parsed.Ciphertext.Length - VaultCrypto.TagSize;
            byte[] pt = VaultCrypto.AllocSecret(ptLen);
            var protector = new TextProtector();
            try
            {
                if (!VaultCrypto.TryOpen(dataKeyRaw, parsed.Nonce, parsed.Aad, parsed.Ciphertext, pt))
                    throw new VaultAuthException();
                var data = Unpad(pt, protector);
                var key = VaultCrypto.ImportDataKey(dataKeyRaw);
                return new VaultSession(path, h, key, protector, data, slotId, policy);
            }
            catch { protector.Dispose(); throw; }
            finally { VaultCrypto.Wipe(pt); }
        }
        finally { VaultCrypto.Wipe(dataKeyRaw); }
    }

    /// <summary>Try every applicable slot. Writes the data key into <paramref name="dataKeyOut"/> and returns the slot id, or null.</summary>
    private static string? UnwrapAny(VaultHeader h, UnlockRequest req, byte[] dataKeyOut)
    {
        if (req.RecoveryKey is not null)
        {
            foreach (var s in h.Slots.Where(s => s.Kind == SlotKind.Recovery))
                if (TryUnwrap(h, s, req.RecoveryKey, dataKeyOut)) return s.Id;
            return null;
        }
        if (req.PasswordUtf8 is null) return null;

        var candidates = h.Slots.Where(s => s.Kind == SlotKind.Password && s.Keyfile == (req.KeyfileHash is not null))
                                .OrderByDescending(s => s.UsesTpm).ToList();
        if (candidates.Count == 0) return null;

        byte[] pwKey = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        try
        {
            VaultCrypto.DerivePasswordKey(req.PasswordUtf8, h.Salt, h.Kdf, pwKey);
            foreach (var s in candidates)
            {
                byte[]? tpmSecret = null;
                if (s.UsesTpm)
                {
                    if (req.Device is null) continue;
                    try { tpmSecret = req.Device.TryUnprotect(s.TpmKeyName!, s.TpmBlob!); }
                    catch (Exception) { tpmSecret = null; }
                    if (tpmSecret is null) continue;
                }
                byte[] ikm = BuildPasswordIkm(pwKey, req.KeyfileHash, tpmSecret);
                try
                {
                    if (TryUnwrap(h, s, ikm, dataKeyOut)) return s.Id;
                }
                finally
                {
                    VaultCrypto.Wipe(ikm);
                    if (tpmSecret is not null) VaultCrypto.Wipe(tpmSecret);
                }
            }
            return null;
        }
        finally { VaultCrypto.Wipe(pwKey); }
    }

    private static bool TryUnwrap(VaultHeader h, KeySlot s, ReadOnlySpan<byte> ikm, byte[] dataKeyOut)
    {
        string ctx = h.SlotContext(s);
        byte[] kek = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        try
        {
            VaultCrypto.Hkdf(ikm, h.SlotHkdfSalt(s), "SVLT/v1/kek|" + ctx, kek);
            if (!VaultCrypto.VerifyCommit(kek, ctx, s.KekCommit)) return false;
            return VaultCrypto.TryOpen(kek, s.Nonce, System.Text.Encoding.UTF8.GetBytes(ctx), s.Wrapped, dataKeyOut);
        }
        finally { VaultCrypto.Wipe(kek); }
    }

    /// <summary>Tagged, length-prefixed concatenation, so different factor combinations can never collide.</summary>
    private static byte[] BuildPasswordIkm(ReadOnlySpan<byte> pwKey, byte[]? keyfileHash, byte[]? tpmSecret)
    {
        int len = 1 + 4 + pwKey.Length + Part(keyfileHash) + Part(tpmSecret);
        byte[] ikm = VaultCrypto.AllocSecret(len);
        int o = 0;
        Put(ikm, ref o, 1, pwKey);
        if (keyfileHash is not null) Put(ikm, ref o, 2, keyfileHash);
        if (tpmSecret is not null) Put(ikm, ref o, 3, tpmSecret);
        return ikm;

        static int Part(byte[]? b) => b is null ? 0 : 1 + 4 + b.Length;
        static void Put(byte[] dst, ref int o, byte tag, ReadOnlySpan<byte> v)
        {
            dst[o++] = tag;
            BinaryPrimitives.WriteInt32LittleEndian(dst.AsSpan(o), v.Length); o += 4;
            v.CopyTo(dst.AsSpan(o)); o += v.Length;
        }
    }

    // ───────────────────────────── Slot construction ─────────────────────────────

    private static string NewSlotId() => Convert.ToHexStringLower(VaultCrypto.RandomBytes(8));

    private static KeySlot MakePasswordSlot(VaultHeader h, byte[] dataKeyRaw, byte[] passwordUtf8, byte[]? keyfileHash, IDeviceKeyProtector? device, string label)
    {
        string id = NewSlotId();
        string? tpmName = device is null ? null : $"SecureVault-{h.VaultId}-{id}";
        byte[]? tpmBlob = null;
        byte[]? tpmSecret = null;
        byte[] pwKey = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        try
        {
            if (device is not null)
            {
                tpmSecret = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
                System.Security.Cryptography.RandomNumberGenerator.Fill(tpmSecret);
                tpmBlob = device.CreateKeyAndProtect(tpmName!, tpmSecret);
            }
            VaultCrypto.DerivePasswordKey(passwordUtf8, h.Salt, h.Kdf, pwKey);
            byte[] ikm = BuildPasswordIkm(pwKey, keyfileHash, tpmSecret);
            try
            {
                var proto = new KeySlot
                {
                    Id = id, Kind = SlotKind.Password, Keyfile = keyfileHash is not null,
                    TpmKeyName = tpmName, TpmBlob = tpmBlob, Label = label,
                    KekCommit = new byte[VaultCrypto.CommitSize], Nonce = [], Wrapped = [],
                };
                return Seal(h, proto, ikm, dataKeyRaw);
            }
            finally { VaultCrypto.Wipe(ikm); }
        }
        catch
        {
            if (tpmName is not null) try { device!.DeleteKey(tpmName); } catch { /* best effort */ }
            throw;
        }
        finally
        {
            VaultCrypto.Wipe(pwKey);
            if (tpmSecret is not null) VaultCrypto.Wipe(tpmSecret);
        }
    }

    private static (KeySlot, string) MakeRecoverySlot(VaultHeader h, byte[] dataKeyRaw)
    {
        var (secret, display) = RecoveryKey.Generate();
        try
        {
            var proto = new KeySlot
            {
                Id = NewSlotId(), Kind = SlotKind.Recovery, Label = "Emergency recovery key",
                KekCommit = new byte[VaultCrypto.CommitSize], Nonce = [], Wrapped = [],
            };
            return (Seal(h, proto, secret, dataKeyRaw), display);
        }
        finally { VaultCrypto.Wipe(secret); }
    }

    private static KeySlot Seal(VaultHeader h, KeySlot proto, ReadOnlySpan<byte> ikm, byte[] dataKeyRaw)
    {
        string ctx = h.SlotContext(proto);
        byte[] kek = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        try
        {
            VaultCrypto.Hkdf(ikm, h.SlotHkdfSalt(proto), "SVLT/v1/kek|" + ctx, kek);
            byte[] nonce = VaultCrypto.RandomBytes(VaultCrypto.NonceSize);
            return new KeySlot
            {
                Id = proto.Id, Kind = proto.Kind, Keyfile = proto.Keyfile, TpmKeyName = proto.TpmKeyName,
                TpmBlob = proto.TpmBlob, Label = proto.Label, Created = proto.Created,
                KekCommit = VaultCrypto.Commit(kek, ctx),
                Nonce = nonce,
                Wrapped = VaultCrypto.Seal(kek, nonce, System.Text.Encoding.UTF8.GetBytes(ctx), dataKeyRaw),
            };
        }
        finally { VaultCrypto.Wipe(kek); }
    }

    // ───────────────────────────── Slot management ─────────────────────────────

    /// <summary>
    /// Add another password-based slot (for example password + TPM on a second PC, or password + keyfile).
    /// Adding a way in doesn't require rotating the data key.
    /// </summary>
    public KeySlot AddPasswordSlot(byte[] passwordUtf8, byte[]? keyfileHash, IDeviceKeyProtector? device, string label)
    {
        byte[] raw = VaultCrypto.ExportDataKey(DataKey);
        KeySlot? slot = null;
        try
        {
            slot = MakePasswordSlot(Header, raw, passwordUtf8, keyfileHash, device, label);
            Header.Slots.Add(slot);
            Save();
            return slot;
        }
        catch
        {
            if (slot is not null)
            {
                Header.Slots.Remove(slot);
                if (slot.UsesTpm) try { device?.DeleteKey(slot.TpmKeyName!); } catch { /* best effort */ }
            }
            throw;
        }
        finally { VaultCrypto.Wipe(raw); }
    }

    public sealed record RekeyResult(IReadOnlyList<KeySlot> DroppedOtherPcTpmSlots, string RecoveryKey);

    /// <summary>
    /// Full re-key after a possible exposure: a NEW random data key, a new salt (and optional KDF), every
    /// password slot rebuilt, and a NEW recovery key. Old backups and old credentials can then no longer
    /// decrypt anything saved from now on.
    ///
    /// This never silently downgrades:
    ///   - if any remaining slot needs a keyfile, <paramref name="keyfileHash"/> must be given and must
    ///     really unlock one of those slots with <paramref name="currentPasswordUtf8"/>, or it throws;
    ///   - TPM slots for THIS PC are rebuilt, and a TPM error aborts the whole operation;
    ///   - TPM slots whose key isn't on this PC (other computers) are dropped and reported;
    ///   - if no password slot would be left, it throws.
    /// </summary>
    public RekeyResult Rekey(byte[] currentPasswordUtf8, byte[] newPasswordUtf8, byte[]? keyfileHash,
        IDeviceKeyProtector? device, KdfParams? newKdf = null, string? removeSlotId = null)
    {
        newKdf ??= Header.Kdf;
        _policy.Enforce(newKdf);
        var oldHeader = Header;
        var keep = oldHeader.Slots.Where(s => s.Kind == SlotKind.Password && s.Id != removeSlotId).ToList();
        if (keep.Count == 0) throw new InvalidOperationException("You can't remove the last password unlock method.");

        if (keep.Any(s => s.Keyfile))
        {
            if (keyfileHash is null) throw new InvalidOperationException("Some unlock methods use a keyfile. Choose that keyfile to continue (nothing was changed).");
            if (!KeyfileUnlocks(oldHeader, keep, currentPasswordUtf8, keyfileHash, device))
                throw new InvalidOperationException("That keyfile doesn't match your keyfile unlock methods (nothing was changed).");
        }

        // Probe the TPM slots first: null = key not on this PC (drop); an exception = TPM error (abort).
        var dropped = new List<KeySlot>();
        var rebuild = new List<KeySlot>();
        foreach (var s in keep)
        {
            if (!s.UsesTpm) { rebuild.Add(s); continue; }
            if (device is null) { dropped.Add(s); continue; }
            byte[]? probe = device.TryUnprotect(s.TpmKeyName!, s.TpmBlob!); // throws on TPM failure → abort
            if (probe is null) { dropped.Add(s); continue; }
            VaultCrypto.Wipe(probe);
            rebuild.Add(s);
        }
        if (rebuild.Count == 0) throw new InvalidOperationException("No unlock method could be rebuilt on this PC (nothing was changed).");

        byte[] newRaw = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        System.Security.Cryptography.RandomNumberGenerator.Fill(newRaw);
        var newHeader = new VaultHeader
        {
            VaultId = oldHeader.VaultId, Counter = oldHeader.Counter, Kdf = newKdf,
            Salt = VaultCrypto.RandomBytes(VaultCrypto.SaltSize),
            DataKeyCommit = VaultCrypto.Commit(newRaw, oldHeader.DataKeyContext),
            Slots = [],
        };
        var createdTpm = new List<string>();
        var oldKey = DataKey;
        bool oldPending = Data.Settings.RecoveryKitPending;
        Key? newKey = null;
        bool swapped = false;
        try
        {
            foreach (var s in rebuild)
            {
                var ns = MakePasswordSlot(newHeader, newRaw, newPasswordUtf8, s.Keyfile ? keyfileHash : null, s.UsesTpm ? device : null, s.Label);
                if (ns.TpmKeyName is not null) createdTpm.Add(ns.TpmKeyName);
                newHeader.Slots.Add(ns);
            }
            var (recoverySlot, display) = MakeRecoverySlot(newHeader, newRaw);
            newHeader.Slots.Add(recoverySlot);
            newKey = VaultCrypto.ImportDataKey(newRaw);

            Header = newHeader; _dataKey = newKey; swapped = true;
            Data.Settings.RecoveryKitPending = true;
            Save();

            oldKey.Dispose();
            // Old TPM keys on this PC (rebuilt slots and the removed slot) are no longer needed.
            foreach (var s in oldHeader.Slots.Where(s => s.UsesTpm && !dropped.Contains(s)))
                try { device?.DeleteKey(s.TpmKeyName!); } catch { /* best effort */ }
            return new RekeyResult(dropped, display);
        }
        catch
        {
            if (swapped) { Header = oldHeader; _dataKey = oldKey; Data.Settings.RecoveryKitPending = oldPending; }
            newKey?.Dispose();
            foreach (var n in createdTpm) try { device?.DeleteKey(n); } catch { /* best effort */ }
            throw;
        }
        finally { VaultCrypto.Wipe(newRaw); }
    }

    /// <summary>True if (password, keyfile) unlocks one of the given keyfile slots of this vault, to the current data key.</summary>
    private bool KeyfileUnlocks(VaultHeader h, List<KeySlot> slots, byte[] password, byte[] keyfileHash, IDeviceKeyProtector? device)
    {
        var view = new VaultHeader
        {
            VaultId = h.VaultId, Counter = h.Counter, Kdf = h.Kdf, Salt = h.Salt, DataKeyCommit = h.DataKeyCommit,
            Slots = slots.Where(s => s.Keyfile).ToList(),
        };
        using var req = new UnlockRequest { PasswordUtf8 = (byte[])password.Clone(), KeyfileHash = (byte[])keyfileHash.Clone(), Device = device };
        byte[] candidate = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        byte[] current = VaultCrypto.ExportDataKey(DataKey);
        try
        {
            return UnwrapAny(view, req, candidate) is not null
                && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(candidate, current);
        }
        finally { VaultCrypto.Wipe(candidate); VaultCrypto.Wipe(current); }
    }

    /// <summary>Change the master password. This also rotates the data key and issues a new recovery key (see <see cref="Rekey"/>).</summary>
    public RekeyResult ChangePassword(byte[] currentPasswordUtf8, byte[] newPasswordUtf8, byte[]? keyfileHash, IDeviceKeyProtector? device, KdfParams? newKdf = null)
        => Rekey(currentPasswordUtf8, newPasswordUtf8, keyfileHash, device, newKdf);

    /// <summary>Remove an unlock method and rotate the data key, so that method can't open future versions even from an old copy.</summary>
    public RekeyResult RemoveSlot(string slotId, byte[] currentPasswordUtf8, byte[]? keyfileHash, IDeviceKeyProtector? device)
    {
        var slot = Header.Slots.SingleOrDefault(s => s.Id == slotId) ?? throw new ArgumentException("No such slot.");
        if (slot.Kind == SlotKind.Recovery) throw new InvalidOperationException("The recovery key can't be removed, only replaced.");
        return Rekey(currentPasswordUtf8, currentPasswordUtf8, keyfileHash, device, removeSlotId: slotId);
    }

    /// <summary>Replace a possibly exposed recovery key, rotating the data key.</summary>
    public RekeyResult ReplaceRecoveryKey(byte[] currentPasswordUtf8, byte[]? keyfileHash, IDeviceKeyProtector? device)
        => Rekey(currentPasswordUtf8, currentPasswordUtf8, keyfileHash, device);

    /// <summary>
    /// Re-issue a recovery key that nobody has seen yet (the kit was closed before it was confirmed). There's no
    /// exposure, so the data key isn't rotated.
    /// </summary>
    public string ReissueUnconfirmedRecoveryKey()
    {
        if (!Data.Settings.RecoveryKitPending) throw new InvalidOperationException("The recovery key was already confirmed. Use ReplaceRecoveryKey.");
        byte[] raw = VaultCrypto.ExportDataKey(DataKey);
        var old = Header.Slots.ToList();
        try
        {
            var (slot, display) = MakeRecoverySlot(Header, raw);
            Header.Slots.RemoveAll(s => s.Kind == SlotKind.Recovery);
            Header.Slots.Add(slot);
            Save();
            return display;
        }
        catch { Header.Slots = old; throw; }
        finally { VaultCrypto.Wipe(raw); }
    }

    /// <summary>The user confirmed they saved the recovery key.</summary>
    public void ConfirmRecoveryKit()
    {
        if (!Data.Settings.RecoveryKitPending) return;
        Data.Settings.RecoveryKitPending = false;
        Save();
    }

    /// <summary>
    /// Delete this vault's encrypted backups. Recommended after a re-key, because the backups are still
    /// readable with the OLD credentials.
    /// </summary>
    public int PurgeBackups()
    {
        string dir = VaultFile.BackupDirectory(Path);
        if (!Directory.Exists(dir)) return 0;
        string stem = System.IO.Path.GetFileNameWithoutExtension(Path), ext = System.IO.Path.GetExtension(Path);
        int n = 0;
        foreach (var f in Directory.GetFiles(dir, stem + "-*" + ext)) { File.Delete(f); n++; }
        return n;
    }

    /// <summary>
    /// Re-authentication before sensitive changes: true only if these credentials unwrap
    /// this vault's own data key through some slot.
    /// </summary>
    public bool VerifyCredentials(UnlockRequest req)
    {
        byte[] candidate = VaultCrypto.AllocSecret(VaultCrypto.KeySize);
        byte[] current = VaultCrypto.ExportDataKey(DataKey);
        try
        {
            return UnwrapAny(Header, req, candidate) is not null
                && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(candidate, current);
        }
        finally { VaultCrypto.Wipe(candidate); VaultCrypto.Wipe(current); }
    }

    /// <summary>Raised after every successful save (used by the app's anti-rollback guard).</summary>
    public event Action<VaultHeader>? Saved;

    // ───────────────────────────── Save / lock ─────────────────────────────

    public void Save()
    {
        long previous = Header.Counter;
        Header.Counter = previous + 1;
        try
        {
            byte[] aad = VaultFile.BuildAad(Header);
            using var w = new PinnedBufferWriter();
            VaultDataSerializer.Write(Data, w);
            byte[] padded = Pad(w.WrittenSpan);
            try
            {
                byte[] nonce = VaultCrypto.RandomBytes(VaultCrypto.NonceSize);
                byte[] ct = VaultCrypto.Seal(DataKey, nonce, aad, padded);
                VaultFile.WriteAtomic(Path, aad, nonce, ct, Data.Settings.MaxBackups, previous);
            }
            finally { VaultCrypto.Wipe(padded); }
        }
        catch { Header.Counter = previous; throw; }
        // The file is committed at this point. A failing listener (e.g. the rollback store) must not make
        // callers think the save failed and roll back in-memory state that no longer matches the disk.
        try { Saved?.Invoke(Header); } catch { /* listener failures are non-fatal */ }
    }

    private static byte[] Pad(ReadOnlySpan<byte> json)
    {
        int total = (4 + json.Length + VaultFile.PadBlock - 1) / VaultFile.PadBlock * VaultFile.PadBlock;
        byte[] buf = VaultCrypto.AllocSecret(total);
        BinaryPrimitives.WriteInt32LittleEndian(buf, json.Length);
        json.CopyTo(buf.AsSpan(4));
        return buf;
    }

    private static VaultData Unpad(ReadOnlySpan<byte> pt, TextProtector p)
    {
        if (pt.Length < 4) throw new VaultFormatException("Vault contents are malformed.");
        int len = BinaryPrimitives.ReadInt32LittleEndian(pt);
        if (len < 0 || len > pt.Length - 4) throw new VaultFormatException("Vault contents are malformed.");
        return VaultDataSerializer.Read(pt.Slice(4, len), p);
    }

    public void Dispose()
    {
        _dataKey?.Dispose(); _dataKey = null;
        _protector?.Dispose(); _protector = null;
        _data?.Entries.Clear(); _data = null;
    }
}
