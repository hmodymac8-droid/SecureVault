using System.Text;
using System.Text.Json;
using SecureVault.Core;

namespace SecureVault.Tests;

public sealed class BrowserProtocolTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("svlt-br-").FullName;
    private readonly VaultSession _s;

    public BrowserProtocolTests()
    {
        using var r = new UnlockRequest { PasswordUtf8 = Encoding.UTF8.GetBytes("correct horse battery staple") };
        (_s, _) = VaultSession.Create(Path.Combine(_dir, "v.pmv"), r, false, new KdfParams(8 * 1024, 1), KdfPolicy.Testing);
        _s.Data.Settings.BrowserEnabled = true;
        Add("GitHub", "https://github.com/login", "octo", "gh-secret");
        Add("Bank", "www.mybank.com", "me", "bank-secret");
        Add("Other", "https://example.org", "x", "other-secret");
    }

    public void Dispose() { _s.Dispose(); Directory.Delete(_dir, true); }

    private void Add(string title, string url, string user, string pw) => _s.Data.Entries.Add(new VaultEntry
    {
        Title = title, Url = url, Username = user,
        Password = ProtectedText.FromChars(_s.Protector, pw), Notes = ProtectedText.Empty(_s.Protector),
    });

    private JsonElement Call(object req, bool allow = true)
    {
        byte[] resp = BrowserProtocol.Handle(_s, JsonSerializer.SerializeToUtf8Bytes(req), (_, _) => allow);
        return JsonDocument.Parse(resp).RootElement.Clone();
    }

    private Guid IdOf(string title) => _s.Data.Entries.Single(e => e.Title == title).Id;

    [Theory]
    [InlineData("https://github.com", "https://github.com/login", true)]
    [InlineData("https://www.github.com", "github.com", true)]
    [InlineData("https://github.com", "www.github.com", true)]
    [InlineData("https://GitHub.com", "https://github.com", true)]
    [InlineData("https://gist.github.com", "github.com", false)]    // no subdomain wildcards
    [InlineData("https://github.com.evil.io", "github.com", false)]
    [InlineData("https://evilgithub.com", "github.com", false)]
    [InlineData("http://github.com", "github.com", false)]          // https only
    [InlineData("https://github.com", "http://github.com", false)]
    [InlineData("https://xn--gthub-n4a.com", "github.com", false)]   // punycode look-alike
    [InlineData("https://github.com:8443", "github.com", false)]     // port must match
    [InlineData("https://github.com/path", "github.com", false)]     // origin must be bare
    [InlineData("https://user@github.com", "github.com", false)]
    [InlineData("https://192.168.1.1", "https://192.168.1.1", false)] // DNS names only
    [InlineData("https://github.com", "", false)]
    public void OriginMatching(string origin, string url, bool expected) => Assert.Equal(expected, BrowserProtocol.OriginMatches(origin, url));

    [Fact]
    public void UnicodeLookalike_DoesNotMatch()
    {
        // "gіthub.com" with a Cyrillic "і" (U+0456): the browser shows it as punycode in the origin.
        var lookalike = new Uri("https://gіthub.com").GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);
        Assert.False(BrowserProtocol.OriginMatches("https://" + new Uri(lookalike).IdnHost, "github.com"));
    }

    [Fact]
    public void Count_And_List_NeverContainPasswords()
    {
        Assert.Equal(1, Call(new { type = "count", origin = "https://github.com" }).GetProperty("count").GetInt32());
        var list = Call(new { type = "list", origin = "https://github.com" });
        string raw = list.GetRawText();
        Assert.Contains("octo", raw);
        Assert.DoesNotContain("gh-secret", raw);
        Assert.Equal(0, Call(new { type = "count", origin = "https://evil.com" }).GetProperty("count").GetInt32());
    }

    [Fact]
    public void Get_ReturnsCredential_OnlyForMatchingSite_AndAfterConfirm()
    {
        var ok = Call(new { type = "get", origin = "https://github.com", id = IdOf("GitHub").ToString() });
        Assert.Equal("gh-secret", ok.GetProperty("password").GetString());
        Assert.Equal("octo", ok.GetProperty("username").GetString());

        // Asking for the bank's password from github.com is refused, without revealing that it exists.
        var cross = Call(new { type = "get", origin = "https://github.com", id = IdOf("Bank").ToString() });
        Assert.Equal("no_match", cross.GetProperty("error").GetString());

        var denied = Call(new { type = "get", origin = "https://github.com", id = IdOf("GitHub").ToString() }, allow: false);
        Assert.Equal("denied", denied.GetProperty("error").GetString());
    }

    [Fact]
    public void ConfirmCanBeTurnedOff()
    {
        _s.Data.Settings.BrowserConfirmEachFill = false;
        var ok = Call(new { type = "get", origin = "https://www.mybank.com", id = IdOf("Bank").ToString() }, allow: false);
        Assert.Equal("bank-secret", ok.GetProperty("password").GetString());
    }

    [Fact]
    public void Disabled_And_BadRequests_AreRefused()
    {
        Assert.Equal("bad_origin", Call(new { type = "list", origin = "http://github.com" }).GetProperty("error").GetString());
        Assert.Equal("bad_request", Call(new { type = "dump" , origin = "https://github.com" }).GetProperty("error").GetString());
        byte[] junk = BrowserProtocol.Handle(_s, "{not json"u8, (_, _) => true);
        Assert.Contains("bad_request", Encoding.UTF8.GetString(junk));
        byte[] huge = BrowserProtocol.Handle(_s, new byte[BrowserProtocol.MaxRequestBytes + 1], (_, _) => true);
        Assert.Contains("bad_request", Encoding.UTF8.GetString(huge));

        _s.Data.Settings.BrowserEnabled = false;
        Assert.Equal("disabled", Call(new { type = "count", origin = "https://github.com" }).GetProperty("error").GetString());
    }
}
