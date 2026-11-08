using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Guardian.Desktop.Vision;

namespace Guardian.Desktop.History;

/// <summary>
/// Local JSONL history. Raw OCR text and screenshots are deliberately excluded.
/// Repeated writes for the same report ID update the logical record when loaded.
/// </summary>
public sealed class GuardianHistoryStore
{
    private const int MaxEntries = 500;
    private static readonly object FileLock = new();

    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Guardian",
        "History",
        "security-history.jsonl");

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true
        };

    public void Save(AnalysisReport report)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

            var entry = new GuardianHistoryEntry
            {
                ReportId = report.Id,
                Timestamp = new DateTimeOffset(report.Timestamp),
                SavedAt = DateTimeOffset.UtcNow,
                Source = report.Source,
                Browser = report.Browser,
                Domain = report.Domain,
                Url = report.ActiveUrl,
                LocalRiskLevel = report.RiskLevel,
                LocalRiskScore = report.RiskScore,
                LocalSummary = report.Summary,
                CloudVerdict = report.CloudAnalysis?.Verdict,
                CloudConfidence = report.CloudAnalysis?.Confidence,
                CloudSummary = report.CloudAnalysis?.Summary,
                CloudModel = report.CloudModel,
                CloudDomainStatus = report.CloudAnalysis?.DomainAssessment?.Status,
                CloudBrand = report.CloudAnalysis?.DomainAssessment?.Brand,
                CloudOfficialDomain = report.CloudAnalysis?.DomainAssessment?.OfficialDomain,
                CloudInputTokens = report.CloudUsage?.InputTokens,
                CloudOutputTokens = report.CloudUsage?.OutputTokens
            };

            string line = JsonSerializer.Serialize(entry, JsonOptions);

            lock (FileLock)
            {
                File.AppendAllText(_path, line + Environment.NewLine);
                TrimIfNeeded();
            }
        }
        catch (IOException)
        {
            // History is best-effort; monitoring and detection must continue.
        }
        catch (UnauthorizedAccessException)
        {
            // History is best-effort; monitoring and detection must continue.
        }
    }

    public IReadOnlyList<GuardianHistoryEntry> LoadRecent(int limit = 100)
    {
        try
        {
            if (!File.Exists(_path))
                return Array.Empty<GuardianHistoryEntry>();

            lock (FileLock)
            {
                return File.ReadLines(_path)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Select(TryDeserialize)
                    .Where(entry => entry != null)
                    .Cast<GuardianHistoryEntry>()
                    .GroupBy(entry => entry.ReportId)
                    .Select(group => group.OrderByDescending(x => x.SavedAt).First())
                    .OrderByDescending(entry => entry.Timestamp)
                    .Take(Math.Clamp(limit, 1, MaxEntries))
                    .ToArray();
            }
        }
        catch (IOException)
        {
            return Array.Empty<GuardianHistoryEntry>();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<GuardianHistoryEntry>();
        }
    }

    private GuardianHistoryEntry? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<GuardianHistoryEntry>(line, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void TrimIfNeeded()
    {
        var entries = File.ReadLines(_path)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(TryDeserialize)
            .Where(entry => entry != null)
            .Cast<GuardianHistoryEntry>()
            .GroupBy(entry => entry.ReportId)
            .Select(group => group.OrderByDescending(x => x.SavedAt).First())
            .OrderByDescending(entry => entry.Timestamp)
            .Take(MaxEntries)
            .OrderBy(entry => entry.Timestamp)
            .ToArray();

        string temporaryPath = _path + ".tmp";
        File.WriteAllLines(
            temporaryPath,
            entries.Select(entry => JsonSerializer.Serialize(entry, JsonOptions)));
        File.Move(temporaryPath, _path, overwrite: true);
    }
}

public sealed record GuardianHistoryEntry
{
    public Guid ReportId { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public DateTimeOffset SavedAt { get; init; }
    public string Source { get; init; } = string.Empty;
    public string Browser { get; init; } = string.Empty;
    public string Domain { get; init; } = string.Empty;
    public string? Url { get; init; }
    public string LocalRiskLevel { get; init; } = "UNKNOWN";
    public int? LocalRiskScore { get; init; }
    public string LocalSummary { get; init; } = string.Empty;
    public string? CloudVerdict { get; init; }
    public int? CloudConfidence { get; init; }
    public string? CloudSummary { get; init; }
    public string? CloudModel { get; init; }
    public string? CloudDomainStatus { get; init; }
    public string? CloudBrand { get; init; }
    public string? CloudOfficialDomain { get; init; }
    public int? CloudInputTokens { get; init; }
    public int? CloudOutputTokens { get; init; }
}
