using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Guardian.Desktop.Cloud;

public sealed record GuardianCloudAnalyzeRequest
{
    [JsonPropertyName("url")]
    public required string Url { get; init; }

    [JsonPropertyName("pageText")]
    public required string PageText { get; init; }

    [JsonPropertyName("heuristicScore")]
    public int HeuristicScore { get; init; }

    [JsonPropertyName("heuristicLevel")]
    public string HeuristicLevel { get; init; } = "UNKNOWN";

    [JsonPropertyName("heuristicReasons")]
    public IReadOnlyList<string> HeuristicReasons { get; init; } = Array.Empty<string>();
}

public sealed record GuardianCloudEnvelope
{
    [JsonPropertyName("success")]
    public bool Success { get; init; }

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "Anthropic";

    [JsonPropertyName("model")]
    public string Model { get; init; } = "Unknown";

    [JsonPropertyName("analysis")]
    public GuardianCloudAnalysis? Analysis { get; init; }

    [JsonPropertyName("usage")]
    public GuardianCloudUsage? Usage { get; init; }

    [JsonPropertyName("timestamp")]
    public DateTimeOffset? Timestamp { get; init; }
}

public sealed record GuardianCloudAnalysis
{
    [JsonPropertyName("verdict")]
    public string Verdict { get; init; } = "UNKNOWN";

    [JsonPropertyName("confidence")]
    public int Confidence { get; init; }

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;

    [JsonPropertyName("indicators")]
    public IReadOnlyList<GuardianCloudIndicator> Indicators { get; init; }
        = Array.Empty<GuardianCloudIndicator>();

    [JsonPropertyName("recommendedAction")]
    public string RecommendedAction { get; init; } = string.Empty;

    [JsonPropertyName("domainAssessment")]
    public GuardianCloudDomainAssessment? DomainAssessment { get; init; }
}

public sealed record GuardianCloudDomainAssessment
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = "UNKNOWN";

    [JsonPropertyName("brand")]
    public string? Brand { get; init; }

    [JsonPropertyName("officialDomain")]
    public string? OfficialDomain { get; init; }

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;
}

public sealed record GuardianCloudIndicator
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("evidence")]
    public string Evidence { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "LOW";
}

public sealed record GuardianCloudUsage
{
    [JsonPropertyName("inputTokens")]
    public int InputTokens { get; init; }

    [JsonPropertyName("outputTokens")]
    public int OutputTokens { get; init; }
}

public sealed record GuardianCloudError
{
    [JsonPropertyName("error")]
    public string Error { get; init; } = "Guardian Cloud request failed.";

    [JsonPropertyName("providerStatus")]
    public int? ProviderStatus { get; init; }

    [JsonPropertyName("providerError")]
    public string? ProviderError { get; init; }
}
