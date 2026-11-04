
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;

namespace Guardian.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly DispatcherTimer _refreshTimer;
    private FileSystemWatcher? _logWatcher;

    private readonly string _logDirectory = Path.Combine(
        Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData),
        "Guardian",
        "Logs");

    public MainWindow()
    {
        InitializeComponent();

        // Compact Guardian window.
        AppWindow.Resize(new SizeInt32(390, 710));

        // Fallback refresh in case file events are missed.
        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2)
        };

        _refreshTimer.Tick += (_, _) => RefreshData();

        InitializeLiveUpdates();

        _refreshTimer.Start();

        RefreshData();

        Closed += OnWindowClosed;
    }

    private void InitializeLiveUpdates()
    {
        Directory.CreateDirectory(_logDirectory);

        _logWatcher = new FileSystemWatcher(_logDirectory)
        {
            Filter = "*.jsonl",
            NotifyFilter =
                NotifyFilters.LastWrite |
                NotifyFilters.FileName |
                NotifyFilters.Size,
            IncludeSubdirectories = false
        };

        _logWatcher.Changed += OnLogChanged;
        _logWatcher.Created += OnLogChanged;
        _logWatcher.Renamed += OnLogRenamed;

        _logWatcher.EnableRaisingEvents = true;
    }

    private void OnLogChanged(
        object sender,
        FileSystemEventArgs e)
    {
        QueueRefresh();
    }

    private void OnLogRenamed(
        object sender,
        RenamedEventArgs e)
    {
        QueueRefresh();
    }

    private void QueueRefresh()
    {
        // FileSystemWatcher callbacks are not on the UI thread.
        DispatcherQueue.TryEnqueue(() =>
        {
            RefreshData();
        });
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        RefreshData();
    }

    private void RefreshData()
    {
        try
        {
            string eventsPath = Path.Combine(
                _logDirectory, "events.jsonl");

            string alertsPath = Path.Combine(
                _logDirectory, "alerts.jsonl");

            string[] eventLines = ReadLogLines(eventsPath);
            string[] alertLines = ReadLogLines(alertsPath);

            int processCount = 0;
            int connectionCount = 0;
            int alertCount = 0;

            string latestEvent = "No events available";
            DateTimeOffset? latestTimestamp = null;

            foreach (string line in eventLines)
            {
                try
                {
                    using JsonDocument document =
                        JsonDocument.Parse(line);

                    JsonElement root = document.RootElement;

                    string type =
                        GetString(root, "Type") ??
                        GetString(root, "type") ??
                        "";

                    if (type == "process_start")
                        processCount++;

                    if (type == "tcp_connection_observed")
                        connectionCount++;

                    if (TryGetTimestamp(
                        root, out DateTimeOffset timestamp))
                    {
                        if (latestTimestamp == null ||
                            timestamp > latestTimestamp.Value)
                        {
                            latestTimestamp = timestamp;
                            latestEvent = BuildEventSummary(root, type);
                        }
                    }
                }
                catch (JsonException)
                {
                    // Ignore incomplete or malformed JSONL records.
                }
            }

            foreach (string line in alertLines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                try
                {
                    using JsonDocument document =
                        JsonDocument.Parse(line);

                    alertCount++;
                }
                catch (JsonException)
                {
                    // Ignore malformed alert records.
                }
            }

            ProcessesText.Text = processCount.ToString("N0");
            ConnectionsText.Text = connectionCount.ToString("N0");
            AlertsText.Text = alertCount.ToString("N0");

            LatestEventText.Text = latestEvent;

            UpdatedText.Text =
                $"Dashboard updated: {DateTime.Now:HH:mm:ss}";

            // Fresh telemetry does not guarantee that
            // the agent is currently running.
            bool recentTelemetry =
                latestTimestamp.HasValue &&
                latestTimestamp.Value >=
                    DateTimeOffset.UtcNow.AddSeconds(-30) &&
                latestTimestamp.Value <=
                    DateTimeOffset.UtcNow.AddMinutes(1);

            if (recentTelemetry)
            {
                StatusText.Text = "Telemetry received";

                StatusText.Foreground = new SolidColorBrush(
                    Colors.LightGreen);

                StatusDescription.Text =
                    "Recent security events detected. " +
                    "Agent health is not independently verified.";
            }
            else
            {
                StatusText.Text = "Status unverified";

                StatusText.Foreground = new SolidColorBrush(
                    Colors.Orange);

                StatusDescription.Text =
                    "No recent telemetry. Start Guardian Agent " +
                    "or wait for new system activity.";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = "Data unavailable";

            StatusText.Foreground = new SolidColorBrush(
                Colors.OrangeRed);

            StatusDescription.Text =
                $"Guardian log error: {ex.Message}";
        }
    }

    private static string BuildEventSummary(
        JsonElement root,
        string type)
    {
        if (type == "process_start")
        {
            string processName =
                GetString(root, "Name") ??
                "Unknown process";

            return $"Process started: {processName}";
        }

        if (type == "tcp_connection_observed")
        {
            string remoteAddress =
                GetString(root, "RemoteAddress") ??
                "Unknown IP";

            string remotePort =
                GetString(root, "RemotePort") ??
                "?";

            return $"TCP: {remoteAddress}:{remotePort}";
        }

        return string.IsNullOrWhiteSpace(type)
            ? "Unknown event"
            : type;
    }

    private static string[] ReadLogLines(string path)
    {
        if (!File.Exists(path))
            return Array.Empty<string>();

        // Allows the agent to append while GUI reads.
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        using var reader = new StreamReader(stream);

        string contents = reader.ReadToEnd();

        return contents.Split(
            new[] { "\r\n", "\n" },
            StringSplitOptions.RemoveEmptyEntries);
    }

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(
            propertyName, out JsonElement value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }

    private static bool TryGetTimestamp(
        JsonElement element,
        out DateTimeOffset timestamp)
    {
        timestamp = default;

        string? value =
            GetString(element, "Timestamp") ??
            GetString(element, "timestamp");

        return DateTimeOffset.TryParse(
            value, out timestamp);
    }

    private void OnWindowClosed(
        object sender,
        WindowEventArgs args)
    {
        _refreshTimer.Stop();

        if (_logWatcher != null)
        {
            _logWatcher.EnableRaisingEvents = false;

            _logWatcher.Changed -= OnLogChanged;
            _logWatcher.Created -= OnLogChanged;
            _logWatcher.Renamed -= OnLogRenamed;

            _logWatcher.Dispose();
            _logWatcher = null;
        }
    }
}
