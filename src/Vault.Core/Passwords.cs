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

public enum StrengthRating { Weak, Fair, Good, Strong }

/// <summary>Result of checking a master password. Only <see cref="Allowed"/> = false blocks it; everything else is advice.</summary>
public sealed record StrengthReport(bool Allowed, StrengthRating Rating, double Bits, string Summary, IReadOnlyList<string> Tips);

/// <summary>
/// Master-password guidance. The hard rules are kept to a minimum (at least 8 characters, not a single
/// repeated character, not one of the best-known passwords). Everything else is a rating plus tips, and the
/// user decides. The estimate counts character variety and length, and only discounts real patterns:
/// repeated characters, runs of 3+ (abc, 321, qwe, asd), and well-known passwords inside it. Ordinary
/// words and sentences aren't penalised.
/// </summary>
public static class PasswordStrength
{
    public const int MinLength = 8;

    private static readonly string[] Common =
    [
        "password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
        "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "trustno1",
        "abc123", "passw0rd", "p@ssword", "p@ssw0rd", "starwars", "whatever", "freedom", "secret",
        "12345678", "123456789", "11111111", "qwertyuiop", "asdfgh", "zxcvbn", "1q2w3e", "iloveu",
    ];
    private static readonly string[] KeyboardRows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

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
        double perChar = Math.Log2(Math.Max(pool, 2));

        Span<char> lower = pw.Length <= 256 ? stackalloc char[pw.Length] : new char[pw.Length];
        pw.ToLowerInvariant(lower);
        try
        {
            // A character counts fully unless it repeats the previous one or continues a run of 3+.
            double effective = 0;
            for (int i = 0; i < lower.Length; i++)
            {
                bool weak = i > 0 && lower[i] == lower[i - 1];
                if (!weak && i >= 2) weak = IsRun(lower[i - 2], lower[i - 1], lower[i]);
                effective += weak ? 0.25 : 1;
            }
            double bits = effective * perChar;

            // Well-known passwords inside it are worth almost nothing.
            foreach (var w in Common)
                if (lower.IndexOf(w.AsSpan()) >= 0) bits -= Math.Max(0, w.Length * perChar - 10);
            return Math.Max(0, bits);
        }
        finally { VaultCrypto.Wipe(lower); }
    }

    /// <summary>abc / cba / 123 / 321, or three neighbouring keys on one keyboard row (qwe, ewq, asd, ...).</summary>
    private static bool IsRun(char a, char b, char c)
    {
        if (b - a == 1 && c - b == 1) return true;
        if (a - b == 1 && b - c == 1) return true;
        foreach (var row in KeyboardRows)
        {
            int ia = row.IndexOf(a), ib = row.IndexOf(b), ic = row.IndexOf(c);
            if (ia < 0 || ib < 0 || ic < 0) continue;
            if ((ib - ia == 1 && ic - ib == 1) || (ia - ib == 1 && ib - ic == 1)) return true;
        }
        return false;
    }

    public static StrengthReport CheckMaster(ReadOnlySpan<char> pw)
    {
        string exampleTip = "Tip: a passphrase of 4–5 random, unrelated words is long, strong and easy to remember, e.g. \"cactus orbit velvet tango lamp\". Don't use song lyrics or famous quotes.";

        // ── Hard minimum: the only things that block ──
        if (pw.Length < MinLength)
            return new(false, StrengthRating.Weak, 0, $"Use at least {MinLength} characters.", [exampleTip]);
        bool allSame = true;
        for (int i = 1; i < pw.Length; i++) if (pw[i] != pw[0]) { allSame = false; break; }
        if (allSame)
            return new(false, StrengthRating.Weak, 0, "A single repeated character is guessed instantly.", [exampleTip]);
        Span<char> lower = pw.Length <= 256 ? stackalloc char[pw.Length] : new char[pw.Length];
        pw.ToLowerInvariant(lower);
        bool isCommon = false;
        foreach (var w in Common) if (lower.SequenceEqual(w.AsSpan())) { isCommon = true; break; }
        VaultCrypto.Wipe(lower);
        if (isCommon)
            return new(false, StrengthRating.Weak, 0, "That's one of the most common passwords; attackers try it first.", [exampleTip]);

        // ── Advice only ──
        double bits = EstimateBits(pw);
        var rating = bits switch { < 45 => StrengthRating.Weak, < 65 => StrengthRating.Fair, < 85 => StrengthRating.Good, _ => StrengthRating.Strong };
        var tips = new List<string>();
        if (rating < StrengthRating.Strong)
        {
            if (pw.Length < 16) tips.Add("Make it longer: length matters most. 16+ characters is a good target.");
            bool hasDigit = false, hasSym = false, hasUpper = false;
            foreach (char c in pw) { hasDigit |= char.IsAsciiDigit(c); hasUpper |= char.IsAsciiLetterUpper(c); hasSym |= !char.IsAsciiLetterOrDigit(c) && c != ' '; }
            if (!hasDigit && !hasSym && pw.Length < 20) tips.Add("Add a number or a symbol somewhere in the middle, not just at the end.");
            if (!hasUpper && pw.Length < 20) tips.Add("A capital letter or two in unexpected places helps a little.");
            tips.Add("Avoid names, birthdays, pet names, keyboard patterns (qwerty, 1234) and swaps like P@ssw0rd; attackers try those first.");
            tips.Add(exampleTip);
        }
        string summary = rating switch
        {
            StrengthRating.Strong => "Strong password.",
            StrengthRating.Good => "Good password.",
            StrengthRating.Fair => "Fair: OK, but it could be stronger.",
            _ => "Weak: it could be guessed fairly quickly if someone copied your vault file.",
        };
        return new(true, rating, bits, summary, tips);
    }
}
