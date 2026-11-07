
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Guardian.Desktop.Vision;

namespace Guardian.Desktop.Vision;

public sealed record PhishingAnalysisResult(
    int Score,
    string RiskLevel,
    string Summary,
    IReadOnlyList<string> Reasons,
    string? AnalyzedUrl
);

public sealed class PhishingAnalyzer
{
    private static readonly string[] LoginIndicators =
    {
        "sign in",
        "log in",
        "login",
        "password",
        "email address",
        "verify your account",
        "zaloguj",
        "zaloguj się",
        "hasło",
        "konto",
        "weryfikacja konta",
        "adres e-mail"
    };

    private static readonly string[] SuspiciousHostKeywords =
    {
        "login",
        "secure",
        "verify",
        "account",
        "password",
        "update",
        "wallet",
        "authentication"
    };

    private static readonly string[] ShortenerDomains =
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd",
        "shorturl.at"
    };

    private static readonly (
        string Brand,
        string[] Domains
    )[] KnownBrands =
    {
        (
            "microsoft",
            new[]
            {
                "microsoft.com",
                "microsoftonline.com",
                "live.com",
                "office.com",
                "outlook.com"
            }
        ),
        (
            "google",
            new[]
            {
                "google.com",
                "google.pl"
            }
        ),
        (
            "paypal",
            new[]
            {
                "paypal.com"
            }
        ),
        (
            "apple",
            new[]
            {
                "apple.com",
                "icloud.com"
            }
        ),
        (
            "amazon",
            new[]
            {
                "amazon.com",
                "amazon.pl"
            }
        )
    };

    public PhishingAnalysisResult Analyze(
        string pageText,
        IEnumerable<string> urlCandidates)
    {
        pageText ??= string.Empty;

        var urls = urlCandidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (urls.Count == 0)
        {
            return new PhishingAnalysisResult(
                0,
                "UNKNOWN",
                "No URL candidates were detected.",
                Array.Empty<string>(),
                null);
        }

        bool loginContext = ContainsLoginIndicators(pageText);

        PhishingAnalysisResult? highestRisk = null;

        foreach (string candidate in urls)
        {
            if (!Uri.TryCreate(
                candidate,
                UriKind.Absolute,
                out Uri? uri))
            {
                continue;
            }

            if (uri.Scheme != Uri.UriSchemeHttp &&
                uri.Scheme != Uri.UriSchemeHttps)
            {
                continue;
            }

            string host = uri.IdnHost.ToLowerInvariant();

            int score = 0;

            var reasons = new List<string>();

            // 1. IP address instead of a domain.
            if (uri.HostNameType == UriHostNameType.IPv4 ||
                uri.HostNameType == UriHostNameType.IPv6)
            {
                AddFinding(
                    ref score,
                    reasons,
                    35,
                    "Website uses an IP address instead of a domain.");
            }

            // 2. Punycode domain.
            if (host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            {
                AddFinding(
                    ref score,
                    reasons,
                    35,
                    "Domain contains an internationalized Punycode label.");
            }

            // 3. User information inside URL.
            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                AddFinding(
                    ref score,
                    reasons,
                    35,
                    "URL contains embedded user information.");
            }

            // 4. HTTP login page.
            if (loginContext &&
                uri.Scheme == Uri.UriSchemeHttp)
            {
                AddFinding(
                    ref score,
                    reasons,
                    20,
                    "Login-related content is displayed over HTTP.");
            }

            // 5. URL shortener.
            if (ShortenerDomains.Any(domain =>
                IsHostOrSubdomain(host, domain)))
            {
                AddFinding(
                    ref score,
                    reasons,
                    15,
                    "URL uses a known link-shortening service.");
            }

            // 6. Excessively nested subdomains.
            if (host.Split('.').Length >= 5)
            {
                AddFinding(
                    ref score,
                    reasons,
                    10,
                    "Domain contains an unusually high number of labels.");
            }

            // 7. Suspicious keywords in login-related URLs.
            if (loginContext &&
                SuspiciousHostKeywords.Any(keyword =>
                    host.Contains(
                        keyword,
                        StringComparison.OrdinalIgnoreCase)))
            {
                AddFinding(
                    ref score,
                    reasons,
                    10,
                    "Login-related page uses security-themed domain keywords.");
            }

            // 8. Brand impersonation.
            if (loginContext)
            {
                foreach (var brand in KnownBrands)
                {
                    bool brandMentioned =
                        pageText.Contains(
                            brand.Brand,
                            StringComparison.OrdinalIgnoreCase);

                    bool brandInHost =
                        host.Contains(
                            brand.Brand,
                            StringComparison.OrdinalIgnoreCase);

                    bool officialDomain =
                        brand.Domains.Any(domain =>
                            IsHostOrSubdomain(host, domain));

                    if ((brandMentioned || brandInHost) &&
                        !officialDomain)
                    {
                        AddFinding(
                            ref score,
                            reasons,
                            35,
                            $"Possible {brand.Brand} impersonation: " +
                            "page branding does not match the domain.");

                        break;
                    }
                }
            }

            // 9. Unusually long URL.
            if (candidate.Length > 120)
            {
                AddFinding(
                    ref score,
                    reasons,
                    5,
                    "URL is unusually long.");
            }

            score = Math.Clamp(score, 0, 100);

            string level = GetRiskLevel(score);

            string summary = score switch
            {
                >= 70 => "Multiple high-risk phishing indicators detected.",
                >= 40 => "Several suspicious website indicators detected.",
                >= 20 => "Some potentially suspicious characteristics detected.",
                _ => "No obvious phishing indicators detected by current rules."
            };

            var result = new PhishingAnalysisResult(
                score,
                level,
                summary,
                reasons,
                candidate);

            if (highestRisk == null ||
                result.Score > highestRisk.Score)
            {
                highestRisk = result;
            }
        }

        return highestRisk ?? new PhishingAnalysisResult(
            0,
            "UNKNOWN",
            "No valid HTTP or HTTPS URLs could be analyzed.",
            Array.Empty<string>(),
            null);
    }

    private static bool ContainsLoginIndicators(string text)
    {
        return LoginIndicators.Any(indicator =>
            text.Contains(
                indicator,
                StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHostOrSubdomain(
        string host,
        string domain)
    {
        return host.Equals(
                   domain,
                   StringComparison.OrdinalIgnoreCase)
               ||
               host.EndsWith(
                   "." + domain,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static void AddFinding(
        ref int score,
        List<string> reasons,
        int points,
        string reason)
    {
        score += points;
        reasons.Add($"+{points}: {reason}");
    }

    private static string GetRiskLevel(int score)
    {
        return score switch
        {
            >= 70 => "CRITICAL",
            >= 40 => "HIGH",
            >= 20 => "MEDIUM",
            _ => "LOW"
        };
    }
}
