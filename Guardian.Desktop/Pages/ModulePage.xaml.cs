using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

using Guardian.Desktop.Domain;
using Guardian.Desktop.Endpoint;
using Guardian.Desktop.History;
using Guardian.Monitoring.Network;

using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml.Navigation;

using Windows.ApplicationModel.DataTransfer;

namespace Guardian.Desktop.Pages;

public sealed partial class ModulePage : Page
{
    private readonly GuardianHistoryStore _history = new();
    private readonly List<ModuleEntry> _entries = new();
    private string _section = "Endpoint";

    public ModulePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _section = e.Parameter?.ToString() ?? "Endpoint";
        LoadSection();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e) => LoadSection();

    private void ModuleSearchBox_TextChanged(object sender, TextChangedEventArgs e) => RenderEntries();

    private void ModuleSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => RenderEntries();

    private void LoadSection()
    {
        _entries.Clear();
        ModuleItemsPanel.Children.Clear();
        ModuleStatsPanel.Children.Clear();
        DomainResultPanel.Children.Clear();
        ModuleSearchBox.Text = string.Empty;
        if (ModuleSeverityFilter != null)
            ModuleSeverityFilter.SelectedIndex = 0;
        DomainToolsPanel.Visibility = _section == "Domain" ? Visibility.Visible : Visibility.Collapsed;

        switch (_section)
        {
            case "Endpoint": LoadEndpoint(); break;
            case "Domain": LoadDomain(); break;
            case "Alerts": LoadAlerts(); break;
            case "History": LoadHistory(); break;
            default:
                ModuleTitleText.Text = "Guardian";
                ModuleDescriptionText.Text = "Select a module from the navigation sidebar.";
                ModuleStatusText.Text = "No module selected.";
                break;
        }

        RenderEntries();
    }

    private void LoadEndpoint()
    {
        ModuleTitleText.Text = "Endpoint explorer";
        ModuleDescriptionText.Text = "Inspect running processes and established IPv4 TCP connections. Select a process to investigate its file metadata, signature and observed network activity.";

        IReadOnlyList<ProcessInventoryItem> processes;
        int inaccessible = 0;
        try
        {
            processes = ProcessInventoryService.GetSnapshot(300);
            inaccessible = processes.Count(item => string.IsNullOrWhiteSpace(item.Path));
        }
        catch (Exception ex)
        {
            processes = Array.Empty<ProcessInventoryItem>();
            ModuleStatusText.Text = $"Process inventory unavailable: {ex.Message}";
        }

        IReadOnlyList<TcpConnectionInfo> connections;
        string networkStatus;
        try
        {
            connections = NetworkMonitor.GetConnections();
            networkStatus = $"{connections.Count} established IPv4 TCP connections returned by Windows.";
        }
        catch (Exception ex)
        {
            connections = Array.Empty<TcpConnectionInfo>();
            networkStatus = $"TCP snapshot unavailable: {ex.Message}";
        }

        AddStat("PROCESSES", processes.Count.ToString("N0"), "Current snapshot", "#245A83");
        AddStat("ESTABLISHED TCP", connections.Count.ToString("N0"), "Current snapshot", "#245A83");
        AddStat("DETAILS LIMITED", inaccessible.ToString("N0"), "Protected or exited", "#66512E");

        ModuleStatusText.Text =
            $"Snapshot at {DateTime.Now:HH:mm:ss}. {processes.Count} processes enumerated (showing up to 150 by working set). {networkStatus} Protected processes may expose limited metadata.";

        foreach (ProcessInventoryItem process in processes.Take(150))
        {
            string path = string.IsNullOrWhiteSpace(process.Path)
                ? "Executable path unavailable (protected process or access denied)."
                : process.Path;

            AddEntry(
                "RUNNING PROCESSES",
                process.Name,
                $"PID {process.ProcessId}  ·  {FormatBytes(process.WorkingSetBytes)} working set",
                path,
                "PROCESS",
                $"{process.Name} {process.ProcessId} {path}",
                process.ProcessId);
        }

        foreach (TcpConnectionInfo connection in connections
            .OrderBy(item => item.ProcessId)
            .ThenBy(item => item.RemoteAddress)
            .Take(150))
        {
            string processName = "Unknown process";
            try
            {
                using Process owner = Process.GetProcessById(connection.ProcessId);
                processName = owner.ProcessName;
            }
            catch (Exception ex) when (
                ex is ArgumentException or InvalidOperationException or
                System.ComponentModel.Win32Exception)
            {
            }

            AddEntry(
                "ESTABLISHED TCP CONNECTIONS",
                $"{connection.RemoteAddress}:{connection.RemotePort}",
                $"{processName}  ·  PID {connection.ProcessId}",
                $"Local {connection.LocalAddress}:{connection.LocalPort}  ->  Remote {connection.RemoteAddress}:{connection.RemotePort}  ·  State ESTABLISHED",
                "TCP",
                $"{processName} {connection.ProcessId} {connection.LocalAddress} {connection.LocalPort} {connection.RemoteAddress} {connection.RemotePort}",
                connection.ProcessId);
        }

        if (processes.Count == 0 && connections.Count == 0)
            AddEntry("STATUS", "No endpoint data available", "Try Refresh.", networkStatus, "INFO", "endpoint empty");
    }

    private void LoadDomain()
    {
        ModuleTitleText.Text = "Domain intelligence";
        ModuleDescriptionText.Text = "Local, explainable hostname checks for official-domain matches, Punycode and possible brand lookalikes. This is not a threat-intelligence or reputation service.";
        ModuleStatusText.Text = "Enter a URL to inspect its hostname. No network request is made by this local check.";

        AddStat("REGISTRY ENTRIES", DomainIntelligenceService.GetRegistry().Count.ToString("N0"), "Built-in domains", "#245A83");
        AddStat("LOOKALIKE CHECK", "ON", "Levenshtein distance", "#245A83");
        AddStat("NETWORK LOOKUPS", "NONE", "Local analysis only", "#17634F");

        DomainInputBox.Text = string.Empty;
        AddEntry("HOW IT WORKS", "Official domain match", "Exact host or subdomain boundary match.", "Example: login.live.com matches live.com. A match is a positive consistency signal, not a safety guarantee.", "INFO", "official domain match");
        AddEntry("HOW IT WORKS", "Possible brand lookalike", "Typographical similarity is a review lead, not a verdict.", "Example: a one-character variation may be shown for manual review. It does not automatically create a HIGH or CRITICAL alert.", "INFO", "typosquatting lookalike");
        AddEntry("HOW IT WORKS", "Unknown domain", "Not present in the built-in registry.", "Unknown does not mean malicious. Guardian does not perform DNS, TLS, WHOIS or external reputation checks in this module.", "INFO", "unknown domain reputation");
    }

    private void AnalyzeDomainButton_Click(object sender, RoutedEventArgs e)
    {
        DomainResultPanel.Children.Clear();
        DomainIntelligenceResult result = DomainIntelligenceService.Analyze(DomainInputBox.Text);

        var title = new TextBlock
        {
            Text = result.Verdict == "LOW" ? "Domain consistency: LOW concern" : result.Verdict == "REVIEW" ? "Domain requires review" : "Domain could not be assessed",
            FontSize = 17,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(result.Verdict == "LOW" ? ColorHelper.FromArgb(255, 101, 220, 174) : result.Verdict == "REVIEW" ? ColorHelper.FromArgb(255, 246, 189, 114) : Colors.White)
        };

        DomainResultPanel.Children.Add(title);
        DomainResultPanel.Children.Add(MakeDetailText($"ASCII hostname: {result.Hostname}"));
        if (!string.Equals(result.UnicodeHostname, result.Hostname, StringComparison.OrdinalIgnoreCase))
            DomainResultPanel.Children.Add(MakeDetailText($"Unicode hostname: {result.UnicodeHostname}"));
        DomainResultPanel.Children.Add(MakeDetailText($"Status: {result.Status}"));
        DomainResultPanel.Children.Add(MakeDetailText($"Punycode: {(result.IsPunycode ? "Yes" : "No")} · Confusable characters: {(result.HasConfusableCharacters ? "Detected" : "Not detected")}"));
        if (!string.IsNullOrWhiteSpace(result.Brand))
            DomainResultPanel.Children.Add(MakeDetailText($"Possible brand: {result.Brand} · Official domain: {result.OfficialDomain}"));
        if (!string.IsNullOrWhiteSpace(result.SimilarDomain))
            DomainResultPanel.Children.Add(MakeDetailText($"Similar label: {result.SimilarDomain} · Edit distance: {result.EditDistance}"));
        DomainResultPanel.Children.Add(MakeDetailText(result.Summary));

        foreach (string finding in result.Findings)
            DomainResultPanel.Children.Add(MakeDetailText("• " + finding));
    }

    private void LoadAlerts()
    {
        ModuleTitleText.Text = "Security alerts";
        ModuleDescriptionText.Text = "A unified, read-only view of endpoint detections and HIGH or CRITICAL local or Claude Vision assessments. Guardian does not automatically block activity.";

        int endpointCount = LoadEndpointAlerts();
        var visionAlerts = _history.LoadRecent(300)
            .Where(x => x.LocalRiskLevel is "HIGH" or "CRITICAL" || x.CloudVerdict is "HIGH" or "CRITICAL")
            .OrderByDescending(x => x.Timestamp)
            .ToArray();

        foreach (var entry in visionAlerts)
        {
            string level = entry.CloudVerdict is "HIGH" or "CRITICAL"
                ? entry.CloudVerdict
                : entry.LocalRiskLevel;

            AddEntry(
                "VISION / CLOUD AI",
                entry.Domain,
                $"{level} · Local {entry.LocalRiskLevel} ({entry.LocalRiskScore?.ToString() ?? "N/A"}/100) · Claude {entry.CloudVerdict ?? "Not run"} · {entry.Timestamp.ToLocalTime():g}",
                entry.CloudSummary ?? entry.LocalSummary,
                level,
                $"{entry.Domain} {level} {entry.LocalSummary} {entry.CloudSummary}");
        }

        ModuleStatusText.Text = $"{endpointCount} endpoint alert records · {visionAlerts.Length} high-risk Vision records. Historical records are informational and may be incomplete.";
        AddStat("ENDPOINT ALERTS", endpointCount.ToString("N0"), "Local JSONL log", "#8A4A38");
        AddStat("VISION ALERTS", visionAlerts.Length.ToString("N0"), "Saved high-risk reports", "#8A4A38");
        AddStat("AUTO BLOCKING", "OFF", "Detection only", "#17634F");

        if (_entries.Count == 0)
            AddEntry("ALL CLEAR", "No high-risk alerts recorded", "No HIGH or CRITICAL findings were found in available local history.", "This does not prove that the device or websites are completely safe.", "LOW", "no alerts");
    }

    private int LoadEndpointAlerts()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Guardian", "Logs", "alerts.jsonl");

        if (!File.Exists(path))
            return 0;

        int count = 0;
        try
        {
            foreach (string line in File.ReadLines(path).TakeLast(300).Reverse())
            {
                try
                {
                    using JsonDocument doc = JsonDocument.Parse(line);
                    JsonElement root = doc.RootElement;
                    string level = ReadString(root, "Level", "UNKNOWN");
                    string name = ReadString(root, "ProcessName", "Unknown process");
                    string reason = ReadString(root, "Reason", "No reason recorded");
                    string timestamp = ReadString(root, "Timestamp", "Timestamp unavailable");
                    string score = ReadString(root, "Score", "N/A");
                    string pid = ReadString(root, "ProcessId", "N/A");

                    AddEntry(
                        "ENDPOINT DETECTION",
                        name,
                        $"{level} · PID {pid} · Score {score} · {timestamp}",
                        reason,
                        level,
                        $"{name} {level} {reason} {timestamp}",
                        int.TryParse(pid, out int parsedPid) ? parsedPid : null);
                    count++;
                }
                catch (JsonException) { }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return count;
    }

    private void LoadHistory()
    {
        ModuleTitleText.Text = "Security history";
        ModuleDescriptionText.Text = "Locally stored Vision reports and Claude assessments. Raw OCR text and screenshots are deliberately excluded from persistent history.";

        var entries = _history.LoadRecent(300);
        ModuleStatusText.Text = $"{entries.Count} recent analysis records · stored locally on this device.";
        AddStat("SAVED REPORTS", entries.Count.ToString("N0"), "Local history", "#245A83");
        AddStat("CLOUD AI", entries.Count(x => x.CloudVerdict != null).ToString("N0"), "Claude assessments", "#245A83");
        AddStat("RAW SCREENSHOTS", "NOT STORED", "Privacy by design", "#17634F");

        foreach (var entry in entries)
        {
            AddEntry(
                "VISION ANALYSIS",
                entry.Domain,
                $"{entry.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss} · Local {entry.LocalRiskLevel} ({entry.LocalRiskScore?.ToString() ?? "N/A"}/100) · Claude {entry.CloudVerdict ?? "Not analyzed"} · Domain {entry.CloudBrand ?? entry.CloudDomainStatus ?? "not checked"}",
                entry.CloudSummary ?? entry.LocalSummary,
                entry.CloudVerdict ?? entry.LocalRiskLevel,
                $"{entry.Domain} {entry.LocalRiskLevel} {entry.CloudVerdict} {entry.LocalSummary} {entry.CloudSummary}");
        }

        if (entries.Count == 0)
            AddEntry("HISTORY", "No saved analyses", "Run a local Vision analysis to create the first record.", "Raw OCR and screenshots are deliberately excluded from persistent history.", "INFO", "empty history");
    }

    private void AddStat(string label, string value, string note, string accent)
    {
        var panel = new StackPanel { Spacing = 6 };
        panel.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 9,
            CharacterSpacing = 85,
            Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 157, 179, 206))
        });
        panel.Children.Add(new TextBlock
        {
            Text = value,
            FontSize = 23,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Colors.White)
        });
        panel.Children.Add(new TextBlock
        {
            Text = note,
            FontSize = 10,
            Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 130, 155, 184)),
            TextWrapping = TextWrapping.Wrap
        });

        ModuleStatsPanel.Children.Add(new Border
        {
            Background = new SolidColorBrush(ColorHelper.FromArgb(255, 23, 40, 62)),
            BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 43, 76, 109)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(11),
            Padding = new Thickness(15),
            MinWidth = 155,
            Child = panel
        });
    }

    private void AddEntry(
        string category,
        string title,
        string subtitle,
        string detail,
        string severity,
        string search,
        int? processId = null)
    {
        _entries.Add(new ModuleEntry(category, title, subtitle, detail, severity, search, processId));
    }

    private void RenderEntries()
    {
        if (ModuleItemsPanel == null)
            return;

        ModuleItemsPanel.Children.Clear();
        string query = ModuleSearchBox?.Text?.Trim() ?? string.Empty;

        var filtered = _entries.AsEnumerable();
        if (!string.IsNullOrWhiteSpace(query))
        {
            filtered = filtered.Where(x => (x.Search + " " + x.Title + " " + x.Detail)
                .Contains(query, StringComparison.OrdinalIgnoreCase));
        }

        string selectedFilter = (ModuleSeverityFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All records";
        if (!string.Equals(selectedFilter, "All records", StringComparison.OrdinalIgnoreCase))
        {
            filtered = filtered.Where(x => string.Equals(
                x.Severity, selectedFilter, StringComparison.OrdinalIgnoreCase));
        }

        var filteredEntries = filtered.ToList();

        if (filteredEntries.Count == 0)
        {
            ModuleItemsPanel.Children.Add(new TextBlock
            {
                Text = "No matching records.",
                Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 157, 179, 206)),
                FontSize = 13,
                Margin = new Thickness(4, 12, 4, 12)
            });
            return;
        }

        foreach (var group in filteredEntries.GroupBy(x => x.Category))
        {
            ModuleItemsPanel.Children.Add(new TextBlock
            {
                Text = group.Key,
                FontSize = 10,
                CharacterSpacing = 100,
                Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 119, 220, 193)),
                Margin = new Thickness(2, 12, 2, 2)
            });

            foreach (var item in group)
            {
                var stack = new StackPanel { Spacing = 7 };
                var titleRow = new Grid { ColumnDefinitions = { new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }, new ColumnDefinition { Width = GridLength.Auto } } };
                var titleText = new TextBlock
                {
                    Text = item.Title,
                    FontSize = 14,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(Colors.White),
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center
                };
                titleRow.Children.Add(titleText);

                var badge = new Border
                {
                    Background = SeverityBrush(item.Severity),
                    CornerRadius = new CornerRadius(7),
                    Padding = new Thickness(9, 4, 9, 4),
                    VerticalAlignment = VerticalAlignment.Center
                };
                badge.Child = new TextBlock
                {
                    Text = item.Severity,
                    FontSize = 9,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Colors.White)
                };
                Grid.SetColumn(badge, 1);
                titleRow.Children.Add(badge);
                stack.Children.Add(titleRow);
                stack.Children.Add(MakeDetailText(item.Subtitle));
                stack.Children.Add(MakeDetailText(item.Detail));

                if (item.ProcessId.HasValue)
                {
                    var action = new Button
                    {
                        Content = "Investigate process",
                        Background = new SolidColorBrush(ColorHelper.FromArgb(255, 39, 91, 132)),
                        Foreground = new SolidColorBrush(Colors.White),
                        Padding = new Thickness(12, 7, 12, 7),
                        CornerRadius = new CornerRadius(7),
                        HorizontalAlignment = HorizontalAlignment.Left
                    };
                    int pid = item.ProcessId.Value;
                    action.Click += async (_, _) => await ShowProcessInvestigationAsync(pid);
                    stack.Children.Add(action);
                }

                ModuleItemsPanel.Children.Add(new Border
                {
                    Background = new SolidColorBrush(ColorHelper.FromArgb(255, 23, 40, 62)),
                    BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 43, 76, 109)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(11),
                    Padding = new Thickness(15),
                    Child = stack
                });
            }
        }
    }

    private async System.Threading.Tasks.Task ShowProcessInvestigationAsync(int processId)
    {
        ProcessInvestigation details;
        try
        {
            details = ProcessInventoryService.GetDetails(processId);
        }
        catch (Exception ex) when (
            ex is ArgumentException or InvalidOperationException or
            System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            await ShowMessageAsync("Process unavailable", "The process may have exited or Windows denied access to its metadata.\n\n" + ex.Message);
            return;
        }

        var text = new StringBuilder();
        text.AppendLine($"Process: {details.Name}");
        text.AppendLine($"PID: {details.ProcessId}");
        text.AppendLine($"Started: {details.StartTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "Unavailable"}");
        text.AppendLine($"Working set: {FormatBytes(details.WorkingSetBytes)}");
        text.AppendLine();
        text.AppendLine("FILE DETAILS");
        text.AppendLine($"Path: {Fallback(details.Path)}");
        text.AppendLine($"Company: {Fallback(details.Company)}");
        text.AppendLine($"Product: {Fallback(details.Product)}");
        text.AppendLine($"Description: {Fallback(details.Description)}");
        text.AppendLine($"Version: {Fallback(details.FileVersion)}");
        text.AppendLine($"Authenticode: {details.SignatureStatus}");
        text.AppendLine();
        text.AppendLine("PROCESS RELATIONSHIP");
        text.AppendLine($"Parent PID: {details.ParentProcessId?.ToString() ?? "Not captured"}");
        text.AppendLine($"Parent name: {details.ParentProcessName}");
        text.AppendLine();
        text.AppendLine("ESTABLISHED TCP CONNECTIONS");
        if (details.TcpConnections.Count == 0)
            text.AppendLine("No established TCP connections observed in the current snapshot.");
        else
            foreach (string connection in details.TcpConnections)
                text.AppendLine(connection);
        text.AppendLine();
        text.AppendLine("Note: missing metadata can result from process protection, access restrictions or a process exiting during collection. An unsigned file is not automatically malicious.");

        string report = text.ToString();
        var reportText = new TextBlock
        {
            Text = report,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
            FontSize = 12,
            Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 213, 224, 237)),
            TextWrapping = TextWrapping.Wrap
        };

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Process investigation",
            Content = new ScrollViewer
            {
                Content = reportText,
                MaxHeight = 520,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            },
            PrimaryButtonText = "Copy details",
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close
        };

        ContentDialogResult result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            var package = new DataPackage();
            package.SetText(report);
            Clipboard.SetContent(package);
        }
    }

    private async System.Threading.Tasks.Task ShowMessageAsync(string title, string message)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = message,
            CloseButtonText = "Close"
        };
        await dialog.ShowAsync();
    }

    private static TextBlock MakeDetailText(string text) => new()
    {
        Text = text,
        FontSize = 12,
        Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 190, 205, 222)),
        TextWrapping = TextWrapping.Wrap
    };

    private static SolidColorBrush SeverityBrush(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => new SolidColorBrush(ColorHelper.FromArgb(255, 145, 43, 55)),
        "HIGH" => new SolidColorBrush(ColorHelper.FromArgb(255, 145, 67, 38)),
        "MEDIUM" => new SolidColorBrush(ColorHelper.FromArgb(255, 130, 103, 42)),
        "LOW" => new SolidColorBrush(ColorHelper.FromArgb(255, 31, 111, 82)),
        "TCP" => new SolidColorBrush(ColorHelper.FromArgb(255, 35, 83, 124)),
        "PROCESS" => new SolidColorBrush(ColorHelper.FromArgb(255, 48, 68, 94)),
        "REVIEW" => new SolidColorBrush(ColorHelper.FromArgb(255, 130, 103, 42)),
        _ => new SolidColorBrush(ColorHelper.FromArgb(255, 68, 80, 99))
    };

    private static string ReadString(JsonElement element, string property, string fallback)
    {
        foreach (JsonProperty item in element.EnumerateObject())
        {
            if (string.Equals(item.Name, property, StringComparison.OrdinalIgnoreCase))
                return item.Value.ToString();
        }
        return fallback;
    }

    private static string Fallback(string value) =>
        string.IsNullOrWhiteSpace(value) ? "Unavailable" : value;

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024 / 1024:N1} GB",
        >= 1024L * 1024 => $"{bytes / 1024d / 1024:N0} MB",
        >= 1024 => $"{bytes / 1024d:N0} KB",
        _ => $"{bytes} B"
    };

    private sealed record ModuleEntry(
        string Category,
        string Title,
        string Subtitle,
        string Detail,
        string Severity,
        string Search,
        int? ProcessId);
}
