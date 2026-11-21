using System.Text.Json;

namespace SecureVault.Core;

public sealed class VaultEntry
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Url { get; set; } = "";
    public required ProtectedText Password { get; set; }
    public required ProtectedText Notes { get; set; }
    public DateTimeOffset Created { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset Modified { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>Per-vault settings, stored encrypted inside the vault so they can't be tampered with.</summary>
public sealed class VaultSettings
{
    public int AutoLockMinutes { get; set; } = 5;
    public int ClipboardClearSeconds { get; set; } = 20;
    public bool LockOnMinimize { get; set; } = true;
    public int MaxBackups { get; set; } = 5;
    /// <summary>A recovery key was issued but the user hasn't confirmed saving it. A new one is issued at the next unlock.</summary>
    public bool RecoveryKitPending { get; set; }

    internal void Clamp()
    {
        AutoLockMinutes = Math.Clamp(AutoLockMinutes, 1, 120);
        ClipboardClearSeconds = Math.Clamp(ClipboardClearSeconds, 5, 120);
        MaxBackups = Math.Clamp(MaxBackups, 0, 50);
    }
}

public sealed class VaultData
{
    public List<VaultEntry> Entries { get; } = [];
    public VaultSettings Settings { get; set; } = new();
}

/// <summary>
/// Hand-written JSON (de)serialisation. Protected fields go straight between pinned buffers and
/// <see cref="ProtectedText"/>, so no plaintext password ever becomes a managed string.
/// </summary>
internal static class VaultDataSerializer
{
    private const int SchemaVersion = 1;
    private const int MaxFieldBytes = 1024 * 1024;

    public static void Write(VaultData data, PinnedBufferWriter output)
    {
        using var w = new Utf8JsonWriter(output, new JsonWriterOptions { SkipValidation = false });
        w.WriteStartObject();
        w.WriteNumber("schema", SchemaVersion);
        w.WriteStartObject("settings");
        w.WriteNumber("autoLockMinutes", data.Settings.AutoLockMinutes);
        w.WriteNumber("clipboardClearSeconds", data.Settings.ClipboardClearSeconds);
        w.WriteBoolean("lockOnMinimize", data.Settings.LockOnMinimize);
        w.WriteNumber("maxBackups", data.Settings.MaxBackups);
        w.WriteBoolean("recoveryKitPending", data.Settings.RecoveryKitPending);
        w.WriteEndObject();
        w.WriteStartArray("entries");
        foreach (var e in data.Entries)
        {
            w.WriteStartObject();
            w.WriteString("id", e.Id);
            w.WriteString("title", e.Title);
            w.WriteString("username", e.Username);
            w.WriteString("url", e.Url);
            WriteProtected(w, "password", e.Password);
            WriteProtected(w, "notes", e.Notes);
            w.WriteString("created", e.Created);
            w.WriteString("modified", e.Modified);
            w.WriteEndObject();
            w.Flush();
        }
        w.WriteEndArray();
        w.WriteEndObject();
        w.Flush();
    }

    public static VaultData Read(ReadOnlySpan<byte> json, TextProtector p)
    {
        var r = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 8 });
        var data = new VaultData();
        Expect(ref r, JsonTokenType.StartObject);
        while (Next(ref r) != JsonTokenType.EndObject)
        {
            string prop = PropName(ref r);
            r.Read();
            switch (prop)
            {
                case "schema":
                    if (r.GetInt32() != SchemaVersion) throw new VaultFormatException("Unsupported vault data version.");
                    break;
                case "settings": data.Settings = ReadSettings(ref r); break;
                case "entries":
                    if (r.TokenType != JsonTokenType.StartArray) throw Bad();
                    while (Next(ref r) != JsonTokenType.EndArray)
                        data.Entries.Add(ReadEntry(ref r, p));
                    break;
                default: r.Skip(); break;
            }
        }
        return data;
    }

    private static VaultSettings ReadSettings(ref Utf8JsonReader r)
    {
        if (r.TokenType != JsonTokenType.StartObject) throw Bad();
        var s = new VaultSettings();
        while (Next(ref r) != JsonTokenType.EndObject)
        {
            string prop = PropName(ref r);
            r.Read();
            switch (prop)
            {
                case "autoLockMinutes": s.AutoLockMinutes = r.GetInt32(); break;
                case "clipboardClearSeconds": s.ClipboardClearSeconds = r.GetInt32(); break;
                case "lockOnMinimize": s.LockOnMinimize = r.GetBoolean(); break;
                case "maxBackups": s.MaxBackups = r.GetInt32(); break;
                case "recoveryKitPending": s.RecoveryKitPending = r.GetBoolean(); break;
                default: r.Skip(); break;
            }
        }
        s.Clamp();
        return s;
    }

    private static VaultEntry ReadEntry(ref Utf8JsonReader r, TextProtector p)
    {
        if (r.TokenType != JsonTokenType.StartObject) throw Bad();
        Guid id = Guid.Empty;
        string title = "", user = "", url = "";
        ProtectedText? pwd = null, notes = null;
        DateTimeOffset created = default, modified = default;
        while (Next(ref r) != JsonTokenType.EndObject)
        {
            string prop = PropName(ref r);
            r.Read();
            switch (prop)
            {
                case "id": id = r.GetGuid(); break;
                case "title": title = r.GetString() ?? ""; break;
                case "username": user = r.GetString() ?? ""; break;
                case "url": url = r.GetString() ?? ""; break;
                case "password": pwd = ReadProtected(ref r, p); break;
                case "notes": notes = ReadProtected(ref r, p); break;
                case "created": created = r.GetDateTimeOffset(); break;
                case "modified": modified = r.GetDateTimeOffset(); break;
                default: r.Skip(); break;
            }
        }
        if (id == Guid.Empty) throw Bad();
        return new VaultEntry
        {
            Id = id, Title = title, Username = user, Url = url,
            Password = pwd ?? ProtectedText.Empty(p),
            Notes = notes ?? ProtectedText.Empty(p),
            Created = created, Modified = modified,
        };
    }

    /// <summary>
    /// Protected fields are written as lowercase hex, built in a pinned buffer. Hex never needs JSON escaping,
    /// so Utf8JsonWriter copies the bytes straight into our pinned output and never through its own
    /// (unwiped) ArrayPool escaping buffers.
    /// </summary>
    private static void WriteProtected(Utf8JsonWriter w, string name, ProtectedText t)
    {
        t.UseUtf8(u =>
        {
            byte[] hex = VaultCrypto.AllocSecret(u.Length * 2);
            try
            {
                for (int i = 0; i < u.Length; i++)
                {
                    hex[2 * i] = Nibble(u[i] >> 4);
                    hex[2 * i + 1] = Nibble(u[i] & 0xF);
                }
                w.WriteString(name, hex);
            }
            finally { VaultCrypto.Wipe(hex); }
        });

        static byte Nibble(int v) => (byte)(v < 10 ? '0' + v : 'a' + v - 10);
    }

    /// <summary>Read a hex-encoded protected field straight from the reader's span into pinned memory.</summary>
    private static ProtectedText ReadProtected(ref Utf8JsonReader r, TextProtector p)
    {
        if (r.TokenType != JsonTokenType.String || r.HasValueSequence || r.ValueIsEscaped) throw Bad();
        ReadOnlySpan<byte> hex = r.ValueSpan;
        if (hex.Length % 2 != 0 || hex.Length / 2 > MaxFieldBytes) throw Bad();
        byte[] buf = VaultCrypto.AllocSecret(hex.Length / 2);
        try
        {
            for (int i = 0; i < buf.Length; i++)
                buf[i] = (byte)((Val(hex[2 * i]) << 4) | Val(hex[2 * i + 1]));
            return ProtectedText.FromUtf8(p, buf);
        }
        finally { VaultCrypto.Wipe(buf); }

        static int Val(byte c) => c switch
        {
            >= (byte)'0' and <= (byte)'9' => c - '0',
            >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
            _ => throw Bad(),
        };
    }

    private static JsonTokenType Next(ref Utf8JsonReader r)
    {
        if (!r.Read()) throw Bad();
        return r.TokenType;
    }

    private static void Expect(ref Utf8JsonReader r, JsonTokenType t)
    {
        if (Next(ref r) != t) throw Bad();
    }

    private static string PropName(ref Utf8JsonReader r)
    {
        if (r.TokenType != JsonTokenType.PropertyName) throw Bad();
        return r.GetString()!;
    }

    private static VaultFormatException Bad() => new("Vault contents are malformed.");
}
