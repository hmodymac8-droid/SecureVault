using System.Text.Json;

namespace SecureVault.Core;

/// <summary>
/// Request handling for the browser extension. Every safety decision is made HERE, inside the vault
/// process, never trusted to the extension:
///   - only https origins, exact host match (a leading "www." is ignored); look-alike Unicode
///     domains are compared in punycode, so they never match
///   - "count" and "list" never return passwords; "list" returns titles and usernames only
///   - "get" returns a password only for an entry that matches the origin, and only after the
///     confirmation callback approves it
///   - strict request size and shape limits
/// </summary>
public static class BrowserProtocol
{
    public const int MaxRequestBytes = 16 * 1024;
    public const int ProtocolVersion = 1;

    public delegate bool ConfirmFill(VaultEntry entry, string host);

    /// <summary>Returns the lowercase punycode host of an exact https origin ("https://host[:port]"), or null.</summary>
    public static string? OriginHost(string origin, out int port)
    {
        port = 0;
        if (origin.Length > 300 || !Uri.TryCreate(origin, UriKind.Absolute, out var o)) return null;
        if (o.Scheme != Uri.UriSchemeHttps || o.UserInfo.Length != 0 || o.AbsolutePath != "/" || o.Query.Length != 0 || o.Fragment.Length != 0) return null;
        if (o.HostNameType is not (UriHostNameType.Dns)) return null;
        port = o.Port;
        return Normalize(o.IdnHost);
    }

    private static string Normalize(string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        return host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;
    }

    /// <summary>
    /// Does a saved entry URL belong to this origin? Only an exact host match counts (ignoring "www."),
    /// with no subdomain wildcards: without the public-suffix list, "co.uk" can't be told apart from a
    /// real site, so wildcards would be unsafe. An entry with no scheme is treated as https.
    /// </summary>
    public static bool OriginMatches(string origin, string entryUrl)
    {
        string? oh = OriginHost(origin, out int oport);
        if (oh is null) return false;
        string u = entryUrl.Trim();
        if (u.Length == 0 || u.Length > 2000) return false;
        if (!u.Contains("://", StringComparison.Ordinal)) u = "https://" + u;
        if (!Uri.TryCreate(u, UriKind.Absolute, out var e) || e.Scheme != Uri.UriSchemeHttps || e.HostNameType != UriHostNameType.Dns) return false;
        return e.Port == oport && Normalize(e.IdnHost) == oh;
    }

    /// <summary>
    /// Handle one request. The returned buffer is pinned and may contain a password: the caller wipes it
    /// after sending.
    /// </summary>
    public static byte[] Handle(VaultSession s, ReadOnlySpan<byte> request, ConfirmFill confirm)
    {
        if (request.Length is 0 or > MaxRequestBytes) return Error("bad_request");
        string? type, origin = null, id = null;
        try
        {
            using var doc = JsonDocument.Parse(request.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return Error("bad_request");
            type = root.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
            if (root.TryGetProperty("origin", out var o) && o.ValueKind == JsonValueKind.String) origin = o.GetString();
            if (root.TryGetProperty("id", out var i) && i.ValueKind == JsonValueKind.String) id = i.GetString();
        }
        catch (JsonException) { return Error("bad_request"); }

        if (s.IsLocked) return Error("locked");
        if (!s.Data.Settings.BrowserEnabled) return Error("disabled");
        if (type == "status") return Write(w => { w.WriteNumber("v", ProtocolVersion); w.WriteBoolean("ok", true); });

        if (origin is null || OriginHost(origin, out _) is not { } host) return Error("bad_origin");
        var matches = s.Data.Entries.Where(e => OriginMatches(origin, e.Url)).ToList();

        switch (type)
        {
            case "count":
                return Write(w => w.WriteNumber("count", matches.Count));

            case "list":
                return Write(w =>
                {
                    w.WriteStartArray("entries");
                    foreach (var e in matches.Take(50))
                    {
                        w.WriteStartObject();
                        w.WriteString("id", e.Id);
                        w.WriteString("title", Trunc(e.Title));
                        w.WriteString("username", Trunc(e.Username));
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                });

            case "get":
                if (!Guid.TryParse(id, out var gid)) return Error("bad_request");
                var entry = matches.FirstOrDefault(e => e.Id == gid);
                if (entry is null) return Error("no_match"); // exists but on another site, or doesn't exist: same answer
                if (s.Data.Settings.BrowserConfirmEachFill && !confirm(entry, host)) return Error("denied");
                return Write(w =>
                {
                    w.WriteString("username", entry.Username);
                    entry.Password.UseUtf8(p => w.WriteString("password", p));
                });

            default:
                return Error("bad_request");
        }
    }

    private static string Trunc(string s) => s.Length <= 200 ? s : s[..200];

    private static byte[] Error(string code) => Write(w => w.WriteString("error", code));

    private static byte[] Write(Action<Utf8JsonWriter> body)
    {
        using var buf = new PinnedBufferWriter(1024);
        using (var w = new Utf8JsonWriter(buf))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        byte[] result = VaultCrypto.AllocSecret(buf.WrittenCount);
        buf.WrittenSpan.CopyTo(result);
        return result;
    }
}
