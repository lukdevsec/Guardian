
using System;
using System.Linq;
using System.Text;
using System.IO;

using Guardian.Desktop.Vision;

using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;

namespace Guardian.Desktop;

public sealed partial class AnalysisDetailsWindow : Window
{
    private readonly AnalysisReport _report;


    public AnalysisDetailsWindow(AnalysisReport report)
    {
        InitializeComponent();

        _report = report;

        Title = "Guardian - Security Analysis Report";

        // Guardian application icon
        string iconPath = Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            "GuardianIcon.ico");

        if (File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }
        else
        {
            System.Diagnostics.Debug.WriteLine(
                $"Guardian report icon not found: {iconPath}");
        }

        AppWindow.Resize(new SizeInt32(850, 680));

        PopulateReport();
    }


    private void PopulateReport()
    {
        ReportTimestampText.Text =
            _report.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");

        ReportDomainText.Text = _report.Domain;

        ReportBrowserText.Text =
            $"Application: {_report.Browser}";

        ReportRiskText.Text = _report.RiskLevel;

        ReportScoreText.Text =
            _report.RiskScore.HasValue
                ? $"{_report.RiskScore.Value}/100"
                : "--/100";

        ReportSummaryText.Text = _report.Summary;

        ReportSourceText.Text =
            $"Analysis source: {_report.Source}";

        ReportActiveUrlText.Text =
            _report.ActiveUrl ?? "Unavailable";

        ReportReasonsText.Text =
            _report.Reasons.Count == 0
                ? "No suspicious indicators detected by current rules."
                : string.Join(
                    Environment.NewLine + Environment.NewLine,
                    _report.Reasons.Select(r => "• " + r));

        ReportOcrUrlsText.Text =
            _report.OcrUrlCandidates.Count == 0
                ? "No URL candidates extracted."
                : string.Join(
                    Environment.NewLine,
                    _report.OcrUrlCandidates);

        ReportOcrText.Text =
            string.IsNullOrWhiteSpace(_report.RecognizedText)
                ? "No readable content detected."
                : _report.RecognizedText;

        if (_report.CloudAnalysis is { } ai)
        {
            ReportAiVerdictText.Text = ai.Verdict;
            ReportAiConfidenceText.Text = $"Confidence: {ai.Confidence}%";
            ReportAiModelText.Text =
                $"Model: {_report.CloudModel ?? "Anthropic Claude"}";

            ReportAiDomainText.Text = ai.DomainAssessment is { } domain
                ? domain.Status == "MATCHED_KNOWN_OFFICIAL_DOMAIN"
                    ? $"Domain registry: {domain.Brand} · official domain match ({domain.OfficialDomain}). This is a domain match, not a safety guarantee."
                    : $"Domain registry: No known official-domain match for {domain.Hostname}. This alone is not evidence of phishing."
                : "Domain registry: Not available in this assessment.";

            ReportAiSummaryText.Text = ai.Summary;
            ReportAiIndicatorsText.Text = ai.Indicators.Count == 0
                ? "No indicators returned by the Cloud AI assessment."
                : string.Join(
                    Environment.NewLine + Environment.NewLine,
                    ai.Indicators.Select(item =>
                        $"• {item.Severity}: {item.Name}\n  Evidence: {item.Evidence}"));
            ReportAiActionText.Text = ai.RecommendedAction;

            ReportAiUsageText.Text = _report.CloudUsage == null
                ? "Token usage unavailable."
                : $"Usage: {_report.CloudUsage.InputTokens:N0} input / {_report.CloudUsage.OutputTokens:N0} output tokens · " +
                  $"Analyzed: {_report.CloudAnalyzedAt?.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
        }
        else
        {
            ReportAiVerdictText.Text = "Not analyzed";
            ReportAiConfidenceText.Text = "Confidence: N/A";
            ReportAiModelText.Text = "Model: Not used";
            ReportAiDomainText.Text = "Domain registry: Not checked";
            ReportAiSummaryText.Text =
                "Cloud AI has not been run for this report. Use 'Analyze latest page with Claude' in Guardian Vision.";
            ReportAiIndicatorsText.Text = "No Cloud AI indicators available.";
            ReportAiActionText.Text = "No recommendation available.";
            ReportAiUsageText.Text = "No API tokens used for Cloud AI.";
        }

        UpdateBadge();
    }

    private void UpdateBadge()
    {
        var color = _report.RiskLevel switch
        {
            "CRITICAL" =>
                ColorHelper.FromArgb(255, 150, 42, 53),

            "HIGH" =>
                ColorHelper.FromArgb(255, 151, 71, 34),

            "MEDIUM" =>
                ColorHelper.FromArgb(255, 135, 107, 38),

            "LOW" =>
                ColorHelper.FromArgb(255, 31, 111, 82),

            _ =>
                ColorHelper.FromArgb(255, 68, 80, 99)
        };

        ReportRiskBadge.Background =
            new SolidColorBrush(color);
    }

    private void CopyReportButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        var builder = new StringBuilder();

        builder.AppendLine("GUARDIAN SECURITY REPORT");
        builder.AppendLine("========================");
        builder.AppendLine(
            $"Date: {_report.Timestamp:yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"Source: {_report.Source}");
        builder.AppendLine($"Browser: {_report.Browser}");
        builder.AppendLine($"Domain: {_report.Domain}");
        builder.AppendLine($"URL: {_report.ActiveUrl ?? "Unavailable"}");
        builder.AppendLine($"Risk: {_report.RiskLevel}");
        builder.AppendLine(
            $"Score: {_report.RiskScore?.ToString() ?? "N/A"}/100");
        builder.AppendLine($"Summary: {_report.Summary}");

        if (_report.CloudAnalysis is { } ai)
        {
            builder.AppendLine();
            builder.AppendLine("CLOUD AI ASSESSMENT");
            builder.AppendLine($"Model: {_report.CloudModel ?? "Anthropic Claude"}");
            builder.AppendLine($"Verdict: {ai.Verdict}");
            builder.AppendLine($"Confidence: {ai.Confidence}%");
            if (ai.DomainAssessment is { } domain)
            {
                string domainLabel = domain.Brand ?? domain.Hostname;
                string officialDomain = domain.OfficialDomain ?? "no registry match";
                builder.AppendLine($"Domain registry: {domain.Status} · {domainLabel} · {officialDomain}");
            }
            builder.AppendLine($"Summary: {ai.Summary}");
            foreach (var indicator in ai.Indicators)
            {
                builder.AppendLine($"- {indicator.Severity}: {indicator.Name} — {indicator.Evidence}");
            }
            builder.AppendLine($"Recommended action: {ai.RecommendedAction}");
        }

        builder.AppendLine();
        builder.AppendLine("DETECTION REASONS");

        foreach (var reason in _report.Reasons)
            builder.AppendLine(reason);

        builder.AppendLine();
        builder.AppendLine("OCR URL CANDIDATES");

        foreach (var url in _report.OcrUrlCandidates)
            builder.AppendLine(url);

        builder.AppendLine();
        builder.AppendLine("RECOGNIZED TEXT");
        builder.AppendLine(_report.RecognizedText);

        CopyText(builder.ToString());
    }

    private void CopyOcrButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        CopyText(_report.RecognizedText);
    }

    private static void CopyText(string text)
    {
        var data = new DataPackage();
        data.SetText(text);

        Clipboard.SetContent(data);
        Clipboard.Flush();
    }
}
