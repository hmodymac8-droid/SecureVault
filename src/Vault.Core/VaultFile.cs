using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SecureVault.Core;

public enum SlotKind { Password = 1, Recovery = 2 }

/// <summary>
/// One independent way to unwrap the data key (like LUKS key slots). Slots can be added or removed
/// without re-encrypting from scratch.
/// </summary>
public sealed class KeySlot
{
    public required string Id { get; init; }
    public required SlotKind Kind { get; init; }
    public string Label { get; set; } = "";
    public DateTimeOffset Created { get; init; } = DateTimeOffset.UtcNow;
    /// <summary>Password slots only: a keyfile is required in addition to the password.</summary>
    public bool Keyfile { get; init; }
    /// <summary>Password slots only: name of the TPM-bound CNG key on one specific PC.</summary>
    public string? TpmKeyName { get; init; }
    /// <summary>32 random bytes, RSA-OAEP encrypted to the TPM key.</summary>
    public byte[]? TpmBlob { get; init; }
    public required byte[] KekCommit { get; init; }
    public required byte[] Nonce { get; init; }
    public required byte[] Wrapped { get; init; }

    [JsonIgnore] public bool UsesTpm => TpmKeyName is not null;
}

public sealed class VaultHeader
{
    public required string VaultId { get; init; }
    public long Counter { get; set; }
    public required KdfParams Kdf { get; set; }
    public required byte[] Salt { get; set; }
    public required byte[] DataKeyCommit { get; init; }
    public required List<KeySlot> Slots { get; set; }

    /// <summary>The canonical context binding a slot to this vault and its KDF settings. Used as AAD, HKDF info and the commitment context.</summary>
    /// Recovery slots don't depend on the password salt or KDF, so a password change leaves the emergency kit valid.
    internal string SlotContext(KeySlot s) => s.Kind == SlotKind.Recovery
        ? $"slot|{VaultId}|{s.Id}|{(int)s.Kind}"
        : $"slot|{VaultId}|{s.Id}|{(int)s.Kind}|kf={(s.Keyfile ? 1 : 0)}|tpm={s.TpmKeyName}|" +
          $"{Kdf.MemoryKiB}|{Kdf.Passes}|{Kdf.Parallelism}|{Convert.ToBase64String(Salt)}";

    /// <summary>HKDF salt for a slot: the password salt for password slots, a vault-id label for recovery slots.</summary>
    internal byte[] SlotHkdfSalt(KeySlot s) => s.Kind == SlotKind.Recovery
        ? System.Text.Encoding.UTF8.GetBytes("SVLT/v1/recovery|" + VaultId)
        : Salt;

    internal string DataKeyContext => $"data|{VaultId}";
}

/// <summary>
/// File layout: "SVLT" | u16 version | u32 headerLen | header JSON | nonce[24] | ciphertext.
/// Everything before the nonce is the AEAD associated data, so any change to the header is detected.
/// </summary>
public static partial class VaultFile
{
    private static ReadOnlySpan<byte> Magic => "SVLT"u8;
    public const ushort FormatVersion = 1;
    private const int PrefixSize = 4 + 2 + 4;
    private const int MaxHeaderSize = 64 * 1024;
    public const long MaxFileSize = 128L * 1024 * 1024;
    public const int PadBlock = 4096;
    private const int MaxSlots = 16;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8,
    };

    [GeneratedRegex("^[0-9a-f]{32}$")] private static partial Regex VaultIdRx();
    [GeneratedRegex("^[0-9a-f]{16}$")] private static partial Regex SlotIdRx();
    [GeneratedRegex("^SecureVault-[0-9a-f]{32}-[0-9a-f]{16}$")] private static partial Regex TpmNameRx();

    public readonly record struct Parsed(VaultHeader Header, byte[] Aad, byte[] Nonce, byte[] Ciphertext);

    public static Parsed Parse(ReadOnlySpan<byte> file, KdfPolicy policy)
    {
        if (file.Length < PrefixSize + 2 + VaultCrypto.NonceSize + VaultCrypto.TagSize || file.Length > MaxFileSize)
            throw new VaultFormatException("Not a vault file (bad size).");
        if (!file[..4].SequenceEqual(Magic)) throw new VaultFormatException("Not a vault file.");
        ushort ver = BinaryPrimitives.ReadUInt16LittleEndian(file[4..]);
        if (ver != FormatVersion) throw new VaultFormatException($"Unsupported vault version {ver}.");
        uint hlen = BinaryPrimitives.ReadUInt32LittleEndian(file[6..]);
        if (hlen == 0 || hlen > MaxHeaderSize || PrefixSize + hlen + VaultCrypto.NonceSize + VaultCrypto.TagSize > file.Length)
            throw new VaultFormatException("Vault header is corrupt.");
        int aadLen = PrefixSize + (int)hlen;

        VaultHeader header;
        try { header = JsonSerializer.Deserialize<VaultHeader>(file.Slice(PrefixSize, (int)hlen), Json) ?? throw new JsonException(); }
        catch (JsonException) { throw new VaultFormatException("Vault header is corrupt."); }
        Validate(header, policy);

        return new Parsed(header, file[..aadLen].ToArray(),
            file.Slice(aadLen, VaultCrypto.NonceSize).ToArray(),
            file[(aadLen + VaultCrypto.NonceSize)..].ToArray());
    }

    /// <summary>Read just the header (no secrets needed). Lets the UI know which factors to ask for.</summary>
    public static VaultHeader ReadHeader(string path, KdfPolicy policy) => Parse(ReadAllBounded(path), policy).Header;

    internal static void Validate(VaultHeader h, KdfPolicy policy)
    {
        static VaultFormatException Bad(string what) => new($"Vault header is corrupt ({what}).");
        if (h.VaultId is null || !VaultIdRx().IsMatch(h.VaultId)) throw Bad("id");
        if (h.Counter < 0) throw Bad("counter");
        if (h.Kdf is null) throw Bad("kdf");
        policy.Enforce(h.Kdf);
        if (h.Salt is not { Length: VaultCrypto.SaltSize }) throw Bad("salt");
        if (h.DataKeyCommit is not { Length: VaultCrypto.CommitSize }) throw Bad("commit");
        if (h.Slots is null || h.Slots.Count is 0 or > MaxSlots) throw Bad("slots");
        var ids = new HashSet<string>();
        int recovery = 0, password = 0;
        foreach (var s in h.Slots)
        {
            if (s is null || s.Id is null || !SlotIdRx().IsMatch(s.Id) || !ids.Add(s.Id)) throw Bad("slot id");
            if (s.Kind is not (SlotKind.Password or SlotKind.Recovery)) throw Bad("slot kind");
            if (s.Nonce is not { Length: VaultCrypto.NonceSize }) throw Bad("slot nonce");
            if (s.Wrapped is not { Length: VaultCrypto.KeySize + VaultCrypto.TagSize }) throw Bad("slot key");
            if (s.KekCommit is not { Length: VaultCrypto.CommitSize }) throw Bad("slot commit");
            if (s.Label is null || s.Label.Length > 100) throw Bad("slot label");
            if (s.Kind == SlotKind.Recovery)
            {
                recovery++;
                if (s.Keyfile || s.TpmKeyName is not null || s.TpmBlob is not null) throw Bad("recovery slot");
            }
            else
            {
                password++;
                if ((s.TpmKeyName is null) != (s.TpmBlob is null)) throw Bad("tpm");
                if (s.TpmKeyName is not null && (!TpmNameRx().IsMatch(s.TpmKeyName) || s.TpmBlob!.Length is 0 or > 1024)) throw Bad("tpm");
            }
        }
        if (recovery > 1 || password == 0) throw Bad("slot set");
    }

    internal static byte[] BuildAad(VaultHeader header)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(header, Json);
        if (json.Length > MaxHeaderSize) throw new VaultFormatException("Header too large.");
        byte[] aad = new byte[PrefixSize + json.Length];
        Magic.CopyTo(aad);
        BinaryPrimitives.WriteUInt16LittleEndian(aad.AsSpan(4), FormatVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(6), (uint)json.Length);
        json.CopyTo(aad, PrefixSize);
        return aad;
    }

    internal static byte[] ReadAllBounded(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (fs.Length > MaxFileSize) throw new VaultFormatException("Vault file too large.");
        byte[] buf = new byte[fs.Length];
        fs.ReadExactly(buf);
        return buf;
    }

    /// <summary>
    /// Atomic write: temp file in the same folder, flushed to disk, then swapped in.
    /// Before the swap, the previous version is copied into backups\ and old backups are pruned.
    /// </summary>
    public static void WriteAtomic(string path, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, int maxBackups, long previousCounter)
    {
        string full = Path.GetFullPath(path);
        string dir = Path.GetDirectoryName(full)!;
        Directory.CreateDirectory(dir);
        string tmp = Path.Combine(dir, "." + Path.GetFileName(full) + "." + Convert.ToHexString(VaultCrypto.RandomBytes(6)) + ".tmp");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                fs.Write(aad);
                fs.Write(nonce);
                fs.Write(ciphertext);
                fs.Flush(true);
            }
            if (File.Exists(full))
            {
                if (maxBackups > 0) Backup(full, maxBackups, previousCounter);
                File.Replace(tmp, full, null, ignoreMetadataErrors: true);
            }
            else File.Move(tmp, full);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    public static string BackupDirectory(string vaultPath) =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(vaultPath))!, "backups");

    private static void Backup(string full, int maxBackups, long counter)
    {
        string bdir = BackupDirectory(full);
        Directory.CreateDirectory(bdir);
        string stem = Path.GetFileNameWithoutExtension(full);
        string name = $"{stem}-{DateTime.UtcNow:yyyyMMdd-HHmmss}-v{counter:D8}{Path.GetExtension(full)}";
        File.Copy(full, Path.Combine(bdir, name), overwrite: true);
        var old = new DirectoryInfo(bdir).GetFiles(stem + "-*" + Path.GetExtension(full))
            .OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(maxBackups);
        foreach (var f in old) f.Delete();
    }
}
