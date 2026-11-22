using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using SecureVault.Core;

namespace SecureVault.Tests;

public class MiscTests
{
    [Fact]
    public void Generator_UsesAllSelectedSets_AndRightLength()
    {
        for (int i = 0; i < 200; i++)
        {
            var pw = PasswordGenerator.Generate(new GeneratorOptions(16));
            Assert.Equal(16, pw.Length);
            Assert.Contains(pw, char.IsAsciiLetterLower);
            Assert.Contains(pw, char.IsAsciiLetterUpper);
            Assert.Contains(pw, char.IsAsciiDigit);
            Assert.DoesNotContain(pw, c => "Il1O0o".Contains(c));
            VaultCrypto.Wipe(pw);
        }
    }

    [Fact]
    public void Generator_DistributionLooksUniform()
    {
        var counts = new Dictionary<char, int>();
        for (int i = 0; i < 2000; i++)
            foreach (char c in PasswordGenerator.Generate(new GeneratorOptions(32, Upper: false, Digits: false, Symbols: false, AvoidAmbiguous: false)))
                counts[c] = counts.GetValueOrDefault(c) + 1;
        Assert.Equal(26, counts.Count);
        double expected = 2000 * 32 / 26.0;
        Assert.All(counts.Values, v => Assert.InRange(v, expected * 0.85, expected * 1.15));
    }

    // Only the hard minimum blocks a password.
    [Theory]
    [InlineData("short1!")]           // under 8 characters
    [InlineData("aaaaaaaaaaaaaaaa")]  // one repeated character
    [InlineData("Password")]          // a top common password
    [InlineData("12345678")]
    public void MasterPassword_HardMinimumBlocks(string pw) => Assert.False(PasswordStrength.CheckMaster(pw).Allowed);

    // Everything else is allowed, with a rating and tips.
    [Theory]
    [InlineData("password123456", StrengthRating.Weak)]
    [InlineData("qwertyuiopasdfgh", StrengthRating.Weak)]
    [InlineData("sunflower", StrengthRating.Weak)]
    [InlineData("tangerine-orbit-velvet-cactus", StrengthRating.Strong)]
    [InlineData("Xq7#mP2!vL9@wR4z", StrengthRating.Strong)]
    // Long ordinary sentences used to be rejected because neighbouring letters (st, de, on...) were penalised.
    [InlineData("my dog loves the beach in summer", StrengthRating.Strong)]
    [InlineData("I want to keep my stuff safe 2026", StrengthRating.Strong)]
    [InlineData("bluehorsestandsonthehill", StrengthRating.Strong)]
    public void MasterPassword_AllowedWithRating(string pw, StrengthRating expected)
    {
        var r = PasswordStrength.CheckMaster(pw);
        Assert.True(r.Allowed);
        Assert.Equal(expected, r.Rating);
        if (expected < StrengthRating.Good) Assert.NotEmpty(r.Tips);
    }

    [Fact]
    public void ProtectedText_RoundTrip_AndDisposedProtectorFails()
    {
        var p = new TextProtector();
        var t = ProtectedText.FromChars(p, "s3cr3t ✓");
        Assert.Equal("s3cr3t ✓", t.RevealToString());
        p.Dispose();
        Assert.Throws<ObjectDisposedException>(() => t.RevealToString());
    }

    [Fact]
    public void Csv_ParsesQuotesAndColumns()
    {
        string dir = Directory.CreateTempSubdirectory("svlt-csv-").FullName;
        try
        {
            string f = Path.Combine(dir, "pw.csv");
            File.WriteAllText(f, "name,url,username,password,note\r\nSite,https://a.com,bob,\"p,\"\"q\",\"multi\nline\"\n,https://b.org/x,al,zz,\n");
            using var p = new TextProtector();
            var e = CsvImport.Import(f, p);
            Assert.Equal(2, e.Count);
            Assert.Equal("p,\"q", e[0].Password.RevealToString());
            Assert.Equal("multi\nline", e[0].Notes.RevealToString());
            Assert.Equal("b.org", e[1].Title);
        }
        finally { Directory.Delete(dir, true); }
    }

    /// <summary>
    /// Static proof the app can't talk to the network: none of our assemblies reference any type in System.Net.
    /// (Runtime-level checks, like a firewall rule, are in the README.)
    /// </summary>
    [Theory]
    [InlineData(typeof(VaultSession))]
    [InlineData(typeof(SecureVault.App.App))]
    public void Assemblies_ReferenceNoNetworking(Type anchor)
    {
        var asm = anchor.Assembly;
        Assert.DoesNotContain(asm.GetReferencedAssemblies(), a =>
            a.Name!.StartsWith("System.Net", StringComparison.Ordinal) && a.Name != "System.Net.Primitives");

        using var pe = new PEReader(File.OpenRead(asm.Location));
        var md = pe.GetMetadataReader();
        var offenders = md.TypeReferences
            .Select(h => md.GetTypeReference(h))
            .Select(t => md.GetString(t.Namespace) + "." + md.GetString(t.Name))
            .Where(n => n.StartsWith("System.Net", StringComparison.Ordinal) || n.StartsWith("System.Web", StringComparison.Ordinal))
            .ToList();
        Assert.Empty(offenders);
    }
}
