using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Guardian.Desktop.Domain;

public sealed record DomainIntelligenceResult(
    string Input,
    string Hostname,
    string Status,
    string Verdict,
    string Summary,
    string? Brand,
    string? OfficialDomain,
    bool IsPunycode,
    bool HasConfusableCharacters,
    string UnicodeHostname,
    string? SimilarDomain,
    int? EditDistance,
    IReadOnlyList<string> Findings);

/// <summary>
/// Local, explainable domain checks. This is not a reputation feed and does not
/// claim a domain is malicious solely because it is unknown or resembles a brand.
/// </summary>
public static class DomainIntelligenceService
{
    private sealed record OfficialDomain(string Brand, string Domain);

    private static readonly OfficialDomain[] Registry =
    {
        new("Microsoft", "microsoft.com"),
        new("Microsoft", "live.com"),
        new("Microsoft", "microsoftonline.com"),
        new("Microsoft", "office.com"),
        new("Microsoft", "outlook.com"),
        new("Google", "google.com"),
        new("Google", "youtube.com"),
        new("GitHub", "github.com"),
        new("PayPal", "paypal.com"),
        new("Amazon", "amazon.com"),
        new("Apple", "apple.com"),
        new("Ledger", "ledger.com"),
        new("Discord", "discord.com"),
        new("Steam", "steampowered.com"),
        new("Steam", "steamcommunity.com"),
        new("Facebook", "facebook.com"),
        new("Instagram", "instagram.com"),
        new("LinkedIn", "linkedin.com"),
        new("Chess.com", "chess.com")
    };

    public static IReadOnlyList<(string Brand, string Domain)> GetRegistry() =>
        Registry.Select(item => (item.Brand, item.Domain)).ToArray();

    public static DomainIntelligenceResult Analyze(string input)
    {
        string value = (input ?? string.Empty).Trim();
        if (!value.Contains("://", StringComparison.Ordinal))
            value = "https://" + value;

        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return new DomainIntelligenceResult(
                value, string.Empty, "INVALID_INPUT", "UNKNOWN",
                "Enter a valid HTTP or HTTPS URL.", null, null,
                false, false, string.Empty, null, null, new[] { "URL could not be parsed." });
        }

        string host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        bool punycode = host.Split('.').Any(label => label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase));
        string unicodeHost = host;
        try { unicodeHost = new IdnMapping().GetUnicode(host); }
        catch (ArgumentException) { }
        bool hasConfusables = unicodeHost.Any(IsConfusableCharacter);

        OfficialDomain? official = Registry
            .Where(item => IsSameOrSubdomain(host, item.Domain))
            .OrderByDescending(item => item.Domain.Length)
            .FirstOrDefault();

        if (official != null)
        {
            var findings = new List<string>
            {
                $"Hostname matches the registered official domain {official.Domain} for {official.Brand}.",
                "A registry match is a positive domain-consistency signal, not a guarantee that the page or account is safe."
            };

            if (punycode)
                findings.Add("The hostname contains an IDN/Punycode label. Review the Unicode representation carefully.");

            return new DomainIntelligenceResult(
                value, host, "OFFICIAL_DOMAIN_MATCH", "LOW",
                $"The hostname is within the known {official.Brand} domain {official.Domain}. No reputation lookup was performed.",
                official.Brand, official.Domain, punycode, hasConfusables,
                unicodeHost, null, null, findings);
        }

        var candidate = FindLookalike(host, unicodeHost);
        var notes = new List<string>();

        if (punycode)
            notes.Add("Punycode/IDN label detected. This is not malicious by itself, but can be used for visual impersonation.");
        if (hasConfusables)
            notes.Add("The Unicode hostname contains characters commonly used as visual confusables. Review the displayed hostname carefully.");

        if (candidate != null)
            notes.Add($"The hostname contains a label visually or typographically similar to {candidate.Value.Brand} ({candidate.Value.Domain}). This is a lead for review, not proof of impersonation.");

        if (notes.Count == 0)
            notes.Add("The hostname is not present in Guardian's small built-in official-domain registry. Unknown does not mean malicious.");

        string status = candidate != null
            ? "POSSIBLE_BRAND_LOOKALIKE"
            : punycode || hasConfusables ? "PUNYCODE_REVIEW" : "NOT_IN_LOCAL_REGISTRY";

        return new DomainIntelligenceResult(
            value, host, status, candidate != null || punycode || hasConfusables ? "REVIEW" : "UNKNOWN",
            candidate != null
                ? "A possible brand lookalike was found. Verify the registrable domain and page context before treating this as a threat."
                : punycode || hasConfusables
                    ? "An internationalized hostname requires visual review. No malicious verdict is inferred."
                    : "No match in the local official-domain registry. No external reputation or DNS check was performed.",
            candidate?.Brand,
            candidate?.Domain,
            punycode,
            hasConfusables,
            unicodeHost,
            candidate?.Label,
            candidate?.Distance,
            notes);
    }

    private static bool IsSameOrSubdomain(string host, string domain) =>
        string.Equals(host, domain, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    private static (string Brand, string Domain, string Label, int Distance)? FindLookalike(string host, string unicodeHost)
    {
        string[] unicodeLabels = unicodeHost.Split('.', StringSplitOptions.RemoveEmptyEntries);
        foreach (string unicodeLabel in unicodeLabels)
        {
            string skeleton = NormalizeConfusables(unicodeLabel);

            foreach (OfficialDomain item in Registry)
            {
                string brandLabel = item.Domain.Split('.')[0];
                if (string.Equals(skeleton, brandLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(unicodeLabel, brandLabel, StringComparison.OrdinalIgnoreCase))
                {
                    return (item.Brand, item.Domain, unicodeLabel, 0);
                }
            }
        }

        // A brand label placed inside a hostname whose actual suffix is not
        // the official root domain is a review signal (for example, brand.example.net).
        foreach (string label in unicodeLabels)
        {
            foreach (OfficialDomain item in Registry)
            {
                string brandLabel = item.Domain.Split('.')[0];
                if (string.Equals(label, brandLabel, StringComparison.OrdinalIgnoreCase))
                    return (item.Brand, item.Domain, label, 0);
            }
        }

        string[] labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Concat(unicodeHost.Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(NormalizeConfusables))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (labels.Length == 0)
            return null;

        // Compare hostname labels to known brand labels. A close match is only
        // surfaced as a review lead; it never automatically creates a HIGH alert.
        var candidates = new List<(string Brand, string Domain, string Label, int Distance)>();

        foreach (string label in labels)
        {
            if (label.Length < 5 || label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (OfficialDomain item in Registry)
            {
                string brandLabel = item.Domain.Split('.')[0];
                if (string.Equals(label, brandLabel, StringComparison.OrdinalIgnoreCase))
                    continue;

                int distance = Levenshtein(label, brandLabel);
                int threshold = brandLabel.Length >= 9 ? 2 : 1;

                if (distance > 0 && distance <= threshold)
                    candidates.Add((item.Brand, item.Domain, label, distance));
            }
        }

        if (candidates.Count == 0)
            return null;

        return candidates
            .OrderBy(candidate => candidate.Distance)
            .ThenByDescending(candidate => candidate.Domain.Length)
            .First();
    }


    private static bool IsConfusableCharacter(char value) => value switch
    {
        '\u0430' or '\u0410' or '\u0435' or '\u0415' or
        '\u043E' or '\u041E' or '\u0440' or '\u0420' or
        '\u0441' or '\u0421' or '\u0445' or '\u0425' or
        '\u0443' or '\u0423' or '\u0456' or '\u0406' or
        '\u0458' or '\u0408' or '\u0455' or '\u0405' or
        '\u03B1' or '\u0391' or '\u03BF' or '\u039F' or
        '\u03C1' or '\u03A1' or '\u03C7' or '\u03A7' => true,
        _ => false
    };

    private static string NormalizeConfusables(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length);
        foreach (char character in value)
        {
            builder.Append(character switch
            {
                '\u0430' or '\u0410' or '\u03B1' or '\u0391' => 'a',
                '\u0435' or '\u0415' => 'e',
                '\u043E' or '\u041E' or '\u03BF' or '\u039F' => 'o',
                '\u0440' or '\u0420' or '\u03C1' or '\u03A1' => 'p',
                '\u0441' or '\u0421' => 'c',
                '\u0445' or '\u0425' or '\u03C7' or '\u03A7' => 'x',
                '\u0443' or '\u0423' => 'y',
                '\u0456' or '\u0406' => 'i',
                '\u0458' or '\u0408' => 'j',
                '\u0455' or '\u0405' => 's',
                _ => char.ToLowerInvariant(character)
            });
        }
        return builder.ToString();
    }

    private static int Levenshtein(string left, string right)
    {
        left = left.ToLowerInvariant();
        right = right.ToLowerInvariant();

        int[,] matrix = new int[left.Length + 1, right.Length + 1];
        for (int i = 0; i <= left.Length; i++) matrix[i, 0] = i;
        for (int j = 0; j <= right.Length; j++) matrix[0, j] = j;

        for (int i = 1; i <= left.Length; i++)
        {
            for (int j = 1; j <= right.Length; j++)
            {
                int cost = left[i - 1] == right[j - 1] ? 0 : 1;
                matrix[i, j] = Math.Min(
                    Math.Min(matrix[i - 1, j] + 1, matrix[i, j - 1] + 1),
                    matrix[i - 1, j - 1] + cost);
            }
        }

        return matrix[left.Length, right.Length];
    }
}
