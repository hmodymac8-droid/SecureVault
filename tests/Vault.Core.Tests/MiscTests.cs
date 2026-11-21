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

    [Theory]
    [InlineData("password123456", false)]
    [InlineData("aaaaaaaaaaaaaaaa", false)]
    [InlineData("qwertyuiopasdfgh", false)]
    [InlineData("short1!", false)]
    [InlineData("tangerine-orbit-velvet-cactus", true)]
    [InlineData("Xq7#mP2!vL9@wR4z", true)]
    public void MasterPasswordStrength(string pw, bool ok) => Assert.Equal(ok, PasswordStrength.CheckMaster(pw).Ok);

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
