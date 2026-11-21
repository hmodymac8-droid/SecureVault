using System.Text;

namespace SecureVault.Core;

/// <summary>
/// Imports password CSVs exported by Chrome, Edge, Firefox or Bitwarden.
/// The CSV itself is plaintext: the UI warns the user to delete it, and that "secure delete" on SSDs isn't reliable.
/// </summary>
public static class CsvImport
{
    private const long MaxSize = 32L * 1024 * 1024;

    public static List<VaultEntry> Import(string path, TextProtector p)
    {
        if (new FileInfo(path).Length > MaxSize) throw new InvalidDataException("CSV file is too large.");
        string text = File.ReadAllText(path, Encoding.UTF8);
        var rows = Parse(text);
        if (rows.Count < 2) return [];

        var head = rows[0].Select(h => h.Trim().ToLowerInvariant()).ToList();
        int Col(params string[] names) => names.Select(n => head.IndexOf(n)).FirstOrDefault(i => i >= 0, -1);
        int cTitle = Col("name", "title"), cUrl = Col("url", "login_uri", "website"),
            cUser = Col("username", "login_username", "user", "email"),
            cPass = Col("password", "login_password"), cNote = Col("note", "notes", "extra", "comments");
        if (cPass < 0) throw new InvalidDataException("No 'password' column found. Is this a password export?");

        var result = new List<VaultEntry>();
        foreach (var r in rows.Skip(1))
        {
            string Get(int i) => i >= 0 && i < r.Count ? r[i] : "";
            if (r.Count == 1 && r[0].Length == 0) continue;
            string url = Get(cUrl), title = Get(cTitle);
            if (title.Length == 0) title = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : "Imported";
            result.Add(new VaultEntry
            {
                Title = title, Url = url, Username = Get(cUser),
                Password = ProtectedText.FromChars(p, Get(cPass)),
                Notes = ProtectedText.FromChars(p, Get(cNote)),
            });
        }
        return result;
    }

    /// <summary>RFC 4180 parser: quoted fields, "" escapes, CRLF or LF line endings.</summary>
    internal static List<List<string>> Parse(string s)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (quoted)
            {
                if (c == '"')
                {
                    if (i + 1 < s.Length && s[i + 1] == '"') { field.Append('"'); i++; }
                    else quoted = false;
                }
                else field.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { row.Add(field.ToString()); field.Clear(); }
            else if (c == '\n' || c == '\r')
            {
                if (c == '\r' && i + 1 < s.Length && s[i + 1] == '\n') i++;
                row.Add(field.ToString()); field.Clear();
                rows.Add(row); row = [];
            }
            else if (c != '﻿' || i != 0) field.Append(c);
        }
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); rows.Add(row); }
        return rows;
    }
}
