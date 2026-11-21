using System.Buffers;
using System.Text;
using NSec.Cryptography;

namespace SecureVault.Core;

public delegate void Utf8Action(ReadOnlySpan<byte> utf8);
public delegate void CharsAction(ReadOnlySpan<char> chars);

/// <summary>
/// Encrypts secrets kept in RAM while the vault is unlocked, using a random per-session key in
/// libsodium guarded memory. A memory dump then shows ciphertext rather than plaintext passwords.
/// Best effort only: anything that can run code in our process can still call Decrypt.
/// </summary>
public sealed class TextProtector : IDisposable
{
    private readonly Key _key = VaultCrypto.CreateEphemeralKey();
    private bool _disposed;

    internal Key Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _key.Dispose();
    }
}

/// <summary>A secret string kept encrypted in memory. Never turned into a System.String unless the caller explicitly asks.</summary>
public sealed class ProtectedText
{
    private readonly TextProtector _protector;
    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;

    public int Utf8Length { get; }
    public bool IsEmpty => Utf8Length == 0;

    private ProtectedText(TextProtector p, ReadOnlySpan<byte> utf8)
    {
        _protector = p;
        Utf8Length = utf8.Length;
        _nonce = VaultCrypto.RandomBytes(VaultCrypto.NonceSize);
        _ciphertext = VaultCrypto.Seal(p.Key, _nonce, default, utf8);
    }

    public static ProtectedText FromUtf8(TextProtector p, ReadOnlySpan<byte> utf8) => new(p, utf8);

    public static ProtectedText FromChars(TextProtector p, ReadOnlySpan<char> chars)
    {
        byte[] buf = VaultCrypto.AllocSecret(Encoding.UTF8.GetMaxByteCount(chars.Length));
        try
        {
            int n = Encoding.UTF8.GetBytes(chars, buf);
            return new ProtectedText(p, buf.AsSpan(0, n));
        }
        finally { VaultCrypto.Wipe(buf); }
    }

    public static ProtectedText Empty(TextProtector p) => new(p, ReadOnlySpan<byte>.Empty);

    /// <summary>Decrypt into a pinned buffer, hand it to <paramref name="use"/>, then wipe it.</summary>
    public void UseUtf8(Utf8Action use)
    {
        byte[] buf = VaultCrypto.AllocSecret(Utf8Length);
        try
        {
            if (!VaultCrypto.TryOpen(_protector.Key, _nonce, default, _ciphertext, buf))
                throw new InvalidOperationException("In-memory secret is corrupted.");
            use(buf);
        }
        finally { VaultCrypto.Wipe(buf); }
    }

    public void UseChars(CharsAction use)
    {
        UseUtf8(utf8 =>
        {
            char[] chars = VaultCrypto.AllocSecretChars(Encoding.UTF8.GetMaxCharCount(utf8.Length));
            try
            {
                int n = Encoding.UTF8.GetChars(utf8, chars);
                use(chars.AsSpan(0, n));
            }
            finally { VaultCrypto.Wipe(chars); }
        });
    }

    /// <summary>
    /// Creates an ordinary .NET string, which can't be wiped. Use only for an explicit "reveal" in the UI.
    /// </summary>
    public string RevealToString()
    {
        string s = "";
        UseChars(c => s = new string(c));
        return s;
    }
}

/// <summary>An IBufferWriter backed by pinned arrays. Old buffers are wiped when it grows, and the last one on Dispose.</summary>
internal sealed class PinnedBufferWriter : IBufferWriter<byte>, IDisposable
{
    private byte[] _buf;
    private int _written;

    public PinnedBufferWriter(int initial = 16 * 1024) => _buf = VaultCrypto.AllocSecret(initial);

    public ReadOnlySpan<byte> WrittenSpan => _buf.AsSpan(0, _written);
    public int WrittenCount => _written;

    public void Advance(int count) => _written += count;

    public Memory<byte> GetMemory(int sizeHint = 0) { Ensure(sizeHint); return _buf.AsMemory(_written); }
    public Span<byte> GetSpan(int sizeHint = 0) { Ensure(sizeHint); return _buf.AsSpan(_written); }

    private void Ensure(int hint)
    {
        hint = Math.Max(hint, 1);
        if (_buf.Length - _written >= hint) return;
        int size = Math.Max(_buf.Length * 2, _written + hint);
        byte[] bigger = VaultCrypto.AllocSecret(size);
        _buf.AsSpan(0, _written).CopyTo(bigger);
        VaultCrypto.Wipe(_buf);
        _buf = bigger;
    }

    public void Dispose() => VaultCrypto.Wipe(_buf);
}
