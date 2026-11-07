
using System;
using System.Collections.Generic;
using System.Linq;

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
    private static readonly HashSet<string> ShortenerDomains =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "cutt.ly",
            "shorturl.at"
        };

    private static readonly string[] LoginIndicators =
    {
        "sign in",
        "log in",
        "login",
        "zaloguj się",
        "zaloguj sie",
        "hasło",
        "password",
        "enter your password",
        "wprowadź hasło",
        "wprowadz haslo"
    };

    private static readonly string[] SuspiciousHostKeywords =
    {
        "verify-account",
        "verify-login",
        "secure-login",
        "account-verification",
        "password-reset",
        "reset-password",
        "confirm-account"
    };

    public PhishingAnalysisResult Analyze(
        string pageText,
        IEnumerable<string> urlCandidates)
    {
        pageText ??= string.Empty;

        bool loginContext = LoginIndicators.Any(
            indicator => pageText.Contains(
                indicator,
                StringComparison.OrdinalIgnoreCase));

        PhishingAnalysisResult? highestRisk = null;

        foreach (string candidate in urlCandidates ??
                 Enumerable.Empty<string>())
        {
            var result = AnalyzeUrl(candidate, loginContext);

            if (result == null)
                continue;

            if (highestRisk == null ||
                result.Score > highestRisk.Score)
            {
                highestRisk = result;
            }
        }

        return highestRisk ??
            new PhishingAnalysisResult(
                0,
                "UNKNOWN",
                "No valid website address was available for analysis.",
                Array.Empty<string>(),
                null);
    }

    private static PhishingAnalysisResult? AnalyzeUrl(
        string candidate,
        bool loginContext)
    {
        if (string.IsNullOrWhiteSpace(candidate))
            return null;

        if (!Uri.TryCreate(
                candidate.Trim(),
                UriKind.Absolute,
                out Uri? uri))
        {
            return null;
        }

        if (uri.Scheme != Uri.UriSchemeHttp &&
            uri.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        int score = 0;
        var reasons = new List<string>();

        string host = uri.Host.ToLowerInvariant();

        // ==========================================
        // 1. IP ADDRESS AS WEBSITE HOST
        // ==========================================

        if (uri.HostNameType == UriHostNameType.IPv4 ||
            uri.HostNameType == UriHostNameType.IPv6)
        {
            score += 20;

            reasons.Add(
                "+20: Website uses an IP address instead of a domain.");
        }

        // ==========================================
        // 2. URL USERINFO
        // ==========================================

        if (!string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            score += 35;

            reasons.Add(
                "+35: URL contains user information before the host. " +
                "This can obscure the actual destination.");
        }

        // ==========================================
        // 3. PUNYCODE INDICATOR
        // ==========================================

        if (host.Split('.').Any(
            part => part.StartsWith(
                "xn--",
                StringComparison.OrdinalIgnoreCase)))
        {
            score += 10;

            reasons.Add(
                "+10: Domain contains an internationalized " +
                "hostname label requiring additional inspection.");
        }

        // ==========================================
        // 4. HTTP WITH LOGIN CONTEXT
        // ==========================================

        if (uri.Scheme == Uri.UriSchemeHttp &&
            loginContext)
        {
            score += 25;

            reasons.Add(
                "+25: Login-related content is displayed " +
                "over an unencrypted HTTP connection.");
        }

        // ==========================================
        // 5. URL SHORTENERS
        // ==========================================

        if (ShortenerDomains.Any(
            domain => IsHostOrSubdomain(host, domain)))
        {
            score += 10;

            reasons.Add(
                "+10: URL shortening service hides " +
                "the final destination.");
        }

        // ==========================================
        // 6. EXCESSIVE SUBDOMAINS
        // ==========================================

        int labelCount = host.Split(
            '.',
            StringSplitOptions.RemoveEmptyEntries).Length;

        if (labelCount >= 6)
        {
            score += 10;

            reasons.Add(
                "+10: Unusually deep hostname structure.");
        }

        // ==========================================
        // 7. SUSPICIOUS HOST KEYWORDS
        // ==========================================

        if (loginContext &&
            SuspiciousHostKeywords.Any(
                keyword => host.Contains(
                    keyword,
                    StringComparison.OrdinalIgnoreCase)))
        {
            score += 10;

            reasons.Add(
                "+10: Domain contains account-verification " +
                "or login-related wording.");
        }

        // ==========================================
        // IMPORTANT: BRAND IMPERSONATION
        // ==========================================

        // Brand mismatch scoring is deliberately disabled.
        //
        // OCR may contain brand names in:
        // - News articles
        // - Advertisements
        // - Browser interface elements
        // - Footer links
        // - Unrelated page content
        //
        // A brand mention alone is NOT evidence
        // of phishing or impersonation.
        //
        // Future AI Context Analyzer will evaluate
        // page purpose, branding and login context
        // with stronger supporting evidence.

        score = Math.Clamp(score, 0, 100);

        string riskLevel = score switch
        {
            >= 70 => "CRITICAL",
            >= 40 => "HIGH",
            >= 20 => "MEDIUM",
            _ => "LOW"
        };

        string summary = riskLevel switch
        {
            "CRITICAL" =>
                "Multiple strong suspicious URL indicators detected.",

            "HIGH" =>
                "Several suspicious URL characteristics detected.",

            "MEDIUM" =>
                "Potentially suspicious URL characteristics detected.",

            _ =>
                "No significant suspicious URL indicators detected " +
                "by the current heuristic rules."
        };

        return new PhishingAnalysisResult(
            score,
            riskLevel,
            summary,
            reasons,
            uri.AbsoluteUri);
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
}
