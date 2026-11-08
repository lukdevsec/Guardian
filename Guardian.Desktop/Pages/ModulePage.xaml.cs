using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;

using Guardian.Desktop.History;
using Guardian.Monitoring.Network;

using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

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

    private void LoadSection()
    {
        _entries.Clear();
        ModuleItemsPanel.Children.Clear();
        ModuleSearchBox.Text = string.Empty;

        switch (_section)
        {
            case "Endpoint": LoadEndpoint(); break;
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
        ModuleTitleText.Text = "Endpoint monitoring";
        ModuleDescriptionText.Text = "Live process inventory and established IPv4 TCP connections on this Windows device.";

        var processes = new List<(long Memory, int Pid, string Name, string Path)>();
        int inaccessible = 0;

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                string name;
                try { name = process.ProcessName; }
                catch { name = "Unknown process"; }

                long memory = 0;
                string path = "Path unavailable (protected or exited)";

                try { memory = process.WorkingSet64; }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }

                try { path = process.MainModule?.FileName ?? path; }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException or UnauthorizedAccessException) { }

                processes.Add((memory, process.Id, name, path));
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                inaccessible++;
            }
            finally
            {
                process.Dispose();
            }
        }

        foreach (var item in processes.OrderByDescending(x => x.Memory).Take(75))
        {
            AddEntry(
                "RUNNING PROCESSES",
                item.Name,
                $"PID {item.Pid} · {FormatBytes(item.Memory)} working set",
                item.Path,
                "PROCESS",
                $"{item.Name} {item.Pid} {item.Path}");
        }

        int connectionCount = 0;
        string networkStatus;
        try
        {
            var connections = NetworkMonitor.GetConnections();
            connectionCount = connections.Count;

            foreach (var connection in connections.Take(120))
            {
                string processName = "Unknown process";
                try
                {
                    using Process owner = Process.GetProcessById(connection.ProcessId);
                    processName = owner.ProcessName;
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }

                AddEntry(
                    "ESTABLISHED TCP CONNECTIONS",
                    $"{connection.RemoteAddress}:{connection.RemotePort}",
                    $"{processName} · PID {connection.ProcessId}",
                    $"Local {connection.LocalAddress}:{connection.LocalPort}  →  Remote {connection.RemoteAddress}:{connection.RemotePort}",
                    "TCP",
                    $"{processName} {connection.ProcessId} {connection.LocalAddress} {connection.LocalPort} {connection.RemoteAddress} {connection.RemotePort}");
            }

            networkStatus = $"{connectionCount} established TCP connections returned by Windows.";
        }
        catch (Exception ex)
        {
            networkStatus = $"TCP snapshot unavailable: {ex.Message}";
        }

        ModuleStatusText.Text =
            $"{processes.Count} processes enumerated · {connectionCount} established TCP connections · {inaccessible} process entries inaccessible. Protected processes may hide details.";

        if (processes.Count == 0 && connectionCount == 0)
            AddEntry("STATUS", "No endpoint data available", networkStatus, "Try Refresh. Some Windows APIs may require elevated permissions.", "INFO", "endpoint empty");
    }

    private void LoadAlerts()
    {
        ModuleTitleText.Text = "Security alerts";
        ModuleDescriptionText.Text = "Endpoint detections and high-risk local or Claude Vision assessments. Alerts are informational; Guardian does not automatically block activity.";

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
                $"{level} · Local {entry.LocalRiskLevel} ({entry.LocalRiskScore?.ToString() ?? "N/A"}/100) · Claude {entry.CloudVerdict ?? "Not run"}",
                entry.CloudSummary ?? entry.LocalSummary,
                level,
                $"{entry.Domain} {level} {entry.LocalSummary} {entry.CloudSummary}");
        }

        ModuleStatusText.Text = $"{endpointCount} endpoint alert records · {visionAlerts.Length} high-risk Vision records.";

        if (_entries.Count == 0)
            AddEntry("ALL CLEAR", "No security alerts recorded", "No HIGH or CRITICAL findings were found in local logs.", "This does not prove that the device or websites are completely safe.", "LOW", "no alerts");
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
            foreach (string line in File.ReadLines(path).TakeLast(200).Reverse())
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

                    AddEntry(
                        "ENDPOINT DETECTION",
                        name,
                        $"{level} · PID {ReadString(root, "ProcessId", "N/A")} · Score {score} · {timestamp}",
                        reason,
                        level,
                        $"{name} {level} {reason} {timestamp}");
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
        ModuleDescriptionText.Text = "Locally stored Vision reports and Claude assessments. Raw OCR text and screenshots are not stored in this history.";

        var entries = _history.LoadRecent(300);
        ModuleStatusText.Text = $"{entries.Count} recent analysis records · stored locally on this device.";

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
            AddEntry("HISTORY", "No saved analyses", "Run a local Vision analysis to create the first history record.", "Raw OCR and screenshots are deliberately excluded from persistent history.", "INFO", "empty history");
    }

    private void AddEntry(string category, string title, string subtitle, string detail, string severity, string search)
    {
        _entries.Add(new ModuleEntry(category, title, subtitle, detail, severity, search));
    }

    private void RenderEntries()
    {
        if (ModuleItemsPanel == null)
            return;

        ModuleItemsPanel.Children.Clear();
        string query = ModuleSearchBox?.Text?.Trim() ?? string.Empty;

        var filtered = string.IsNullOrWhiteSpace(query)
            ? _entries
            : _entries.Where(x => (x.Search + " " + x.Title + " " + x.Detail)
                .Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();

        if (filtered.Count == 0)
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

        foreach (var group in filtered.GroupBy(x => x.Category))
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
                var stack = new StackPanel { Spacing = 6 };
                var titleRow = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 10
                };
                titleRow.Children.Add(new TextBlock
                {
                    Text = item.Title,
                    FontSize = 14,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(Colors.White),
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center
                });

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
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                    Foreground = new SolidColorBrush(Colors.White)
                };
                titleRow.Children.Add(badge);
                stack.Children.Add(titleRow);
                stack.Children.Add(new TextBlock
                {
                    Text = item.Subtitle,
                    FontSize = 11,
                    Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 157, 179, 206)),
                    TextWrapping = TextWrapping.Wrap
                });
                stack.Children.Add(new TextBlock
                {
                    Text = item.Detail,
                    FontSize = 12,
                    Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 205, 218, 233)),
                    TextWrapping = TextWrapping.Wrap
                });

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

    private static SolidColorBrush SeverityBrush(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => new SolidColorBrush(ColorHelper.FromArgb(255, 145, 43, 55)),
        "HIGH" => new SolidColorBrush(ColorHelper.FromArgb(255, 145, 67, 38)),
        "MEDIUM" => new SolidColorBrush(ColorHelper.FromArgb(255, 130, 103, 42)),
        "LOW" => new SolidColorBrush(ColorHelper.FromArgb(255, 31, 111, 82)),
        "TCP" => new SolidColorBrush(ColorHelper.FromArgb(255, 35, 83, 124)),
        "PROCESS" => new SolidColorBrush(ColorHelper.FromArgb(255, 48, 68, 94)),
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
        string Search);
}
