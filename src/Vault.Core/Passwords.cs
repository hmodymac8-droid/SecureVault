using System.Security.Cryptography;

namespace SecureVault.Core;

public sealed record GeneratorOptions(int Length = 24, bool Lower = true, bool Upper = true, bool Digits = true, bool Symbols = true, bool AvoidAmbiguous = true);

public static class PasswordGenerator
{
    private const string LowerSet = "abcdefghijklmnopqrstuvwxyz", UpperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        DigitSet = "0123456789", SymbolSet = "!@#$%^&*()-_=+[]{};:,.<>/?~";
    private const string Ambiguous = "Il1O0o|`'\"";

    /// <summary>
    /// Returns the password in a pinned buffer; the caller must wipe it.
    /// RandomNumberGenerator.GetInt32 is unbiased (it rejection-samples internally).
    /// </summary>
    public static char[] Generate(GeneratorOptions o)
    {
        if (o.Length is < 8 or > 256) throw new ArgumentOutOfRangeException(nameof(o), "Length must be 8 to 256.");
        var sets = new List<string>();
        if (o.Lower) sets.Add(LowerSet);
        if (o.Upper) sets.Add(UpperSet);
        if (o.Digits) sets.Add(DigitSet);
        if (o.Symbols) sets.Add(SymbolSet);
        if (sets.Count == 0) throw new ArgumentException("Pick at least one character set.");
        if (o.AvoidAmbiguous) sets = sets.Select(s => new string(s.Where(c => !Ambiguous.Contains(c)).ToArray())).ToList();
        string pool = string.Concat(sets);

        char[] result = VaultCrypto.AllocSecretChars(o.Length);
        for (int attempt = 0; ; attempt++)
        {
            for (int i = 0; i < result.Length; i++) result[i] = pool[RandomNumberGenerator.GetInt32(pool.Length)];
            // Re-draw the whole password (not patch it) so the distribution stays uniform over valid outputs.
            if (sets.All(s => result.AsSpan().IndexOfAny(s) >= 0) || attempt > 1000) return result;
        }
    }

    public static double EntropyBits(GeneratorOptions o)
    {
        int pool = (o.Lower ? 26 : 0) + (o.Upper ? 26 : 0) + (o.Digits ? 10 : 0) + (o.Symbols ? SymbolSet.Length : 0);
        if (o.AvoidAmbiguous) pool -= 6;
        return pool <= 1 ? 0 : o.Length * Math.Log2(pool);
    }
}

/// <summary>
/// A conservative master-password strength estimate. It's a simple heuristic, not a full zxcvbn: it
/// counts character pools, then penalises repeats, sequences, keyboard runs and well-known passwords.
/// </summary>
public static class PasswordStrength
{
    public const int MinLength = 12;
    public const double MinBits = 60;

    private static readonly string[] Common =
    [
        "password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
        "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "trustno1",
        "abc123", "passw0rd", "p@ssword", "p@ssw0rd", "starwars", "whatever", "freedom", "secret",
    ];
    private const string Rows = "qwertyuiopasdfghjklzxcvbnm1234567890";

    public static double EstimateBits(ReadOnlySpan<char> pw)
    {
        if (pw.IsEmpty) return 0;
        bool lo = false, up = false, di = false, sy = false, uni = false;
        foreach (char c in pw)
        {
            if (char.IsAsciiLetterLower(c)) lo = true;
            else if (char.IsAsciiLetterUpper(c)) up = true;
            else if (char.IsAsciiDigit(c)) di = true;
            else if (c < 128) sy = true;
            else uni = true;
        }
        int pool = (lo ? 26 : 0) + (up ? 26 : 0) + (di ? 10 : 0) + (sy ? 33 : 0) + (uni ? 100 : 0);

        // Count "effective" characters: repeats of the previous char, or steps in a sequence/keyboard row, count as a quarter.
        double effective = 1;
        for (int i = 1; i < pw.Length; i++)
        {
            char a = char.ToLowerInvariant(pw[i - 1]), b = char.ToLowerInvariant(pw[i]);
            bool weak = a == b || Math.Abs(a - b) == 1;
            int ia = Rows.IndexOf(a), ib = Rows.IndexOf(b);
            if (ia >= 0 && ib >= 0 && Math.Abs(ia - ib) == 1) weak = true;
            effective += weak ? 0.25 : 1;
        }
        double bits = effective * Math.Log2(Math.Max(pool, 2));

        Span<char> lower = pw.Length <= 256 ? stackalloc char[pw.Length] : new char[pw.Length];
        pw.ToLowerInvariant(lower);
        foreach (var w in Common)
            if (lower.IndexOf(w.AsSpan()) >= 0) bits -= w.Length * Math.Log2(Math.Max(pool, 2)) - 10;
        VaultCrypto.Wipe(lower);
        return Math.Max(0, bits);
    }

    public static (bool Ok, string Message) CheckMaster(ReadOnlySpan<char> pw)
    {
        if (pw.Length < MinLength) return (false, $"Use at least {MinLength} characters. A few random words work well.");
        double bits = EstimateBits(pw);
        if (bits < MinBits) return (false, $"Too guessable (about {bits:F0} bits; need {MinBits:F0}+). Make it longer and less predictable.");
        return (true, $"Strong enough (about {bits:F0} bits).");
    }
}
