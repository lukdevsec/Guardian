
using System;
using System.Collections.Generic;
using Guardian.Desktop.Cloud;

namespace Guardian.Desktop.Vision;

public sealed record AnalysisReport(
    DateTime Timestamp,
    string Source,
    string Browser,
    string Domain,
    string? ActiveUrl,
    IReadOnlyList<string> OcrUrlCandidates,
    string RiskLevel,
    int? RiskScore,
    string Summary,
    IReadOnlyList<string> Reasons,
    string RecognizedText
)
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public GuardianCloudAnalysis? CloudAnalysis { get; init; }

    public GuardianCloudUsage? CloudUsage { get; init; }

    public string? CloudModel { get; init; }

    public DateTimeOffset? CloudAnalyzedAt { get; init; }
}
