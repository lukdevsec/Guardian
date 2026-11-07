
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Guardian.Desktop.Vision;

public sealed class UrlExtractor
{
    private static readonly Regex UrlPattern = new(
        @"(?ix)
        (?<![@\w.-])
        (?:
            https?://[^\s<>""']+
            |
            www\.[^\s<>""']+
            |
            (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
            [a-z]{2,}
            (?::\d{1,5})?
            (?:/[^\s<>""']*)?
        )",
        RegexOptions.Compiled |
        RegexOptions.IgnoreCase |
        RegexOptions.CultureInvariant);

    public IReadOnlyList<string> Extract(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<string>();

        var results = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);

        foreach (Match match in UrlPattern.Matches(text))
        {
            string candidate = match.Value.Trim(
                '.', ',', ';', ':', '!', '?',
                ')', ']', '}', '"', '\'');

            if (string.IsNullOrWhiteSpace(candidate))
                continue;

            string normalized = candidate;

            if (normalized.StartsWith(
                "www.",
                StringComparison.OrdinalIgnoreCase))
            {
                normalized = "https://" + normalized;
            }
            else if (!normalized.StartsWith(
                "http://",
                StringComparison.OrdinalIgnoreCase) &&
                !normalized.StartsWith(
                "https://",
                StringComparison.OrdinalIgnoreCase))
            {
                normalized = "https://" + normalized;
            }

            if (!Uri.TryCreate(
                normalized,
                UriKind.Absolute,
                out Uri? uri))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(uri.Host))
                continue;

            if (!uri.Host.Contains('.'))
                continue;

            results.Add(uri.ToString());
        }

        return results.ToList();
    }
}
