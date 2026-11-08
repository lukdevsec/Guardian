using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Guardian.Desktop.Vision;

namespace Guardian.Desktop.Cloud;

public sealed class GuardianCloudException : Exception
{
    public int? HttpStatusCode { get; }
    public string? ProviderError { get; }

    public GuardianCloudException(
        string message,
        int? httpStatusCode = null,
        string? providerError = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        HttpStatusCode = httpStatusCode;
        ProviderError = providerError;
    }
}

/// <summary>
/// Calls the private Guardian Cloud Worker. Only URL, OCR text and local
/// heuristic findings are sent. Screen images are never uploaded by this client.
/// </summary>
public sealed class GuardianCloudClient
{
    private const string Endpoint =
        "https://guardian-cloud-api.warszawskimail7.workers.dev/api/analyze";

    private const int MaxTextLength = 12000;

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(45)
    };

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true
        };

    private static readonly ConcurrentDictionary<string, CacheEntry> Cache = new();
    private static readonly ConcurrentDictionary<string, DateTimeOffset> LastDomainRequest = new();

    public bool IsConfigured => GuardianCloudTokenStore.IsConfigured;

    public async Task<GuardianCloudEnvelope> AnalyzeAsync(
        AnalysisReport report,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(report.ActiveUrl) ||
            !Uri.TryCreate(report.ActiveUrl, UriKind.Absolute, out Uri? pageUri) ||
            (pageUri.Scheme != Uri.UriSchemeHttp && pageUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new GuardianCloudException(
                "Guardian Vision does not have a verified HTTP/HTTPS page URL.");
        }

        if (string.IsNullOrWhiteSpace(report.RecognizedText))
        {
            throw new GuardianCloudException(
                "There is no recognized page text to analyze.");
        }

        string token = GuardianCloudTokenStore.Load()
            ?? throw new GuardianCloudException(
                "Guardian Cloud access token is not configured for this Windows user. Run Scripts\\Setup-GuardianCloudToken.ps1.");

        string pageText = report.RecognizedText.Length > MaxTextLength
            ? report.RecognizedText[..MaxTextLength]
            : report.RecognizedText;

        string cacheKey = CreateCacheKey(pageUri.AbsoluteUri, pageText);

        if (Cache.TryGetValue(cacheKey, out CacheEntry? cached) &&
            DateTimeOffset.UtcNow - cached.CreatedAt < TimeSpan.FromMinutes(10))
        {
            return cached.Response;
        }

        string domainKey = pageUri.IdnHost.ToLowerInvariant();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (LastDomainRequest.TryGetValue(domainKey, out DateTimeOffset previousRequest) &&
            now - previousRequest < TimeSpan.FromSeconds(20))
        {
            throw new GuardianCloudException(
                "A Cloud AI request for this domain was sent recently. Wait 20 seconds before requesting another analysis.");
        }
        LastDomainRequest[domainKey] = now;

        var requestBody = new GuardianCloudAnalyzeRequest
        {
            Url = pageUri.AbsoluteUri,
            PageText = pageText,
            HeuristicScore = Math.Clamp(report.RiskScore ?? 0, 0, 100),
            HeuristicLevel = report.RiskLevel,
            HeuristicReasons = report.Reasons
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(requestBody, JsonOptions),
            Encoding.UTF8,
            "application/json");

        using HttpResponseMessage response = await Http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        string responseJson = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            GuardianCloudError? error = null;

            try
            {
                error = JsonSerializer.Deserialize<GuardianCloudError>(
                    responseJson,
                    JsonOptions);
            }
            catch (JsonException)
            {
                // Do not expose raw provider response content in the UI.
            }

            string message = response.StatusCode switch
            {
                System.Net.HttpStatusCode.Unauthorized =>
                    "Guardian Cloud rejected its access token. Re-run the token setup script.",
                System.Net.HttpStatusCode.TooManyRequests =>
                    "Guardian Cloud rate limit reached. Wait before trying again.",
                System.Net.HttpStatusCode.BadGateway =>
                    $"Claude request failed: {error?.ProviderError ?? error?.Error ?? "upstream error"}.",
                _ =>
                    $"Guardian Cloud returned HTTP {(int)response.StatusCode}: {error?.Error ?? "request failed"}."
            };

            throw new GuardianCloudException(
                message,
                (int)response.StatusCode,
                error?.ProviderError);
        }

        GuardianCloudEnvelope? result;

        try
        {
            result = JsonSerializer.Deserialize<GuardianCloudEnvelope>(
                responseJson,
                JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new GuardianCloudException(
                "Guardian Cloud returned an unreadable analysis response.",
                (int)response.StatusCode,
                innerException: ex);
        }

        if (result?.Success != true || result.Analysis == null)
        {
            throw new GuardianCloudException(
                "Guardian Cloud response did not contain a completed analysis.",
                (int)response.StatusCode);
        }

        Cache[cacheKey] = new CacheEntry(DateTimeOffset.UtcNow, result);
        PruneCache();
        return result;
    }

    private static void PruneCache()
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10);

        foreach (var item in Cache)
        {
            if (item.Value.CreatedAt < cutoff)
                Cache.TryRemove(item.Key, out _);
        }

        if (Cache.Count > 200)
        {
            foreach (var item in Cache.OrderBy(pair => pair.Value.CreatedAt).Take(Cache.Count - 200))
                Cache.TryRemove(item.Key, out _);
        }

        if (LastDomainRequest.Count > 500)
        {
            DateTimeOffset requestCutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10);
            foreach (var item in LastDomainRequest)
            {
                if (item.Value < requestCutoff)
                    LastDomainRequest.TryRemove(item.Key, out _);
            }
        }
    }

    private static string CreateCacheKey(string url, string text)
    {
        byte[] input = Encoding.UTF8.GetBytes(url + "\n" + text);
        byte[] hash = SHA256.HashData(input);
        return Convert.ToHexString(hash);
    }

    private sealed record CacheEntry(
        DateTimeOffset CreatedAt,
        GuardianCloudEnvelope Response);
}
