
using System;
using System.Collections.Generic;

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
);
