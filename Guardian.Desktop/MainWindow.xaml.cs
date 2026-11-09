
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Guardian.Desktop.Notifications;
using Guardian.Desktop.Cloud;
using Guardian.Desktop.History;
using Guardian.Desktop.Pages;
using Guardian.Desktop.UI;
using Guardian.Desktop.Vision;
using Guardian.Service.IPC;

using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

using Windows.Graphics;
using Windows.Graphics.Imaging;

using WinUIEx;

namespace Guardian.Desktop;

public sealed partial class MainWindow : Window
{
    // ==========================================
    // CORE COMPONENTS
    // ==========================================

    private readonly TelemetryState _telemetry;

    private readonly DispatcherTimer _refreshTimer;

    private readonly WindowManager _windowManager;

    // ==========================================
    // VISION COMPONENTS
    // ==========================================

    private readonly ScreenCaptureManager _screenCapture = new();

    private readonly ContinuousScreenMonitor _continuousMonitor = new();

    private readonly BrowserAddressReader _browserAddressReader = new();

    private readonly UrlExtractor _urlExtractor = new();

    private readonly PhishingAnalyzer _phishingAnalyzer = new();

    private ScreenTextRecognizer? _textRecognizer;

    // ==========================================
    // NOTIFICATIONS
    // ==========================================

    private readonly NotificationService _notifications;

    private readonly GuardianCloudClient _cloudClient = new();

    private readonly GuardianHistoryStore _historyStore = new();

    // ==========================================
    // REPORTS
    // ==========================================

    private AnalysisReport? _latestReport;

    private AnalysisReport? _latestAlertReport;

    private AnalysisDetailsWindow? _detailsWindow;

    private readonly List<AnalysisReport> _sessionHistory = new();

    // ==========================================
    // APPLICATION STATE
    // ==========================================

    private bool _visionBusy;

    private bool _cloudBusy;

    private bool _continuousStarting;

    private bool _allowClose;

    private string? _lastContinuousFingerprint;

    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;

    private string? _lastActivityFingerprint;

    // ==========================================
    // CONSTRUCTOR
    // ==========================================

    public MainWindow(TelemetryState telemetry)
    {
        InitializeComponent();

        _telemetry = telemetry;

        Title = "Guardian";

        // Premium desktop window.
        AppWindow.Resize(new SizeInt32(1280, 820));
        ApplyTitleBarTheme();

        // ======================================
        // GUARDIAN APPLICATION ICON
        // ======================================

        string iconPath = System.IO.Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            "GuardianIcon.ico");

        if (File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }
        else
        {
            Debug.WriteLine(
                $"Guardian icon not found: {iconPath}");
        }

        // ======================================
        // INITIAL DASHBOARD STATE
        // ======================================

        DashboardContent.Visibility = Visibility.Visible;
        VisionContent.Visibility = Visibility.Collapsed;
        SettingsContent.Visibility = Visibility.Collapsed;
        ModuleFrame.Visibility = Visibility.Collapsed;

        // Select Dashboard.
        if (RootNavigation.MenuItems.Count > 0)
        {
            RootNavigation.SelectedItem =
                RootNavigation.MenuItems[0];
        }

        // ======================================
        // SYSTEM TRAY
        // ======================================

        _windowManager = WindowManager.Get(this);

        _windowManager.IsVisibleInTray = true;

        _windowManager.TrayIconSelected += (_, _) =>
        {
            ShowGuardianWindow();
        };

        _windowManager.TrayIconContextMenu += (_, e) =>
        {
            var menu = new MenuFlyout();

            var openItem = new MenuFlyoutItem
            {
                Text = "Open Guardian"
            };

            openItem.Click += (_, _) =>
            {
                ShowGuardianWindow();
            };

            var exitItem = new MenuFlyoutItem
            {
                Text = "Exit Guardian"
            };

            exitItem.Click += async (_, _) =>
            {
                try
                {
                    _allowClose = true;

                    _refreshTimer?.Stop();

                    ContinuousVisionButton.IsEnabled = false;

                    await _continuousMonitor.StopAsync();

                    _windowManager.IsVisibleInTray = false;

                    _detailsWindow?.Close();

                    await ((App)Application.Current)
                        .ShutdownAsync();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(
                        $"Guardian shutdown error: {ex}");
                }
            };

            menu.Items.Add(openItem);

            menu.Items.Add(
                new MenuFlyoutSeparator());

            menu.Items.Add(exitItem);

            e.Flyout = menu;
        };

        // X hides Guardian in system tray.
        AppWindow.Closing += (_, e) =>
        {
            if (!_allowClose)
            {
                e.Cancel = true;

                AppWindow.Hide();
            }
        };

        // ======================================
        // TELEMETRY TIMER
        // ======================================

        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };

        _refreshTimer.Tick += (_, _) =>
        {
            RefreshData();

            RefreshContinuousMonitoringStatus();
        };

        _refreshTimer.Start();

        Closed += OnWindowClosed;

        // ======================================
        // NOTIFICATION SERVICE
        // ======================================

        _notifications = new NotificationService();

        _notifications.NotificationClicked += () =>
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                ShowGuardianWindow();

                OpenAnalysisDetails(
                    _latestAlertReport ?? _latestReport);
            });
        };

        NotificationStatusText.Text =
            _notifications.IsAvailable
                ? "Windows notifications initialized"
                : "Windows notifications unavailable";

        // ======================================
        // INITIAL VISION STATE
        // ======================================

        ContinuousVisionButton.Content =
            "Start continuous monitoring";

        ContinuousVisionStatusText.Text =
            "Continuous monitoring inactive";

        VisionStatusText.Text =
            "No website analyzed";

        VisionDomainText.Text =
            "No active website";

        VisionRiskBadgeText.Text =
            "UNKNOWN";

        VisionScoreText.Text =
            "--/100";

        VisionSummaryText.Text =
            "Start a screen analysis to view security findings.";

        VisionDetailsButton.IsEnabled = false;
        CloudAiButton.IsEnabled = false;
        VisionAiVerdictText.Text = "Not analyzed";
        CloudAiStatusText.Text = _cloudClient.IsConfigured
            ? "Guardian Cloud ready · Claude analysis runs only when requested."
            : "Cloud token not configured. Run Scripts\\Setup-GuardianCloudToken.ps1 once on this Windows account.";

        CloudAiDashboardText.Text = _cloudClient.IsConfigured
            ? "Configured"
            : "Not set up";
        CloudAiDashboardText.Foreground = new SolidColorBrush(
            _cloudClient.IsConfigured
                ? ColorHelper.FromArgb(255, 101, 220, 174)
                : Colors.Orange);

        // ======================================
        // INITIAL ENDPOINT STATE
        // ======================================

        RefreshData();

        Debug.WriteLine(
            "Guardian Premium Desktop initialized.");
    }

    // ==========================================
    // WINDOW CHROME
    // ==========================================

    private void ApplyTitleBarTheme()
    {
        try
        {
            if (!AppWindowTitleBar.IsCustomizationSupported())
                return;

            var titleBar = AppWindow.TitleBar;
            var background = ColorHelper.FromArgb(255, 5, 19, 36);

            titleBar.BackgroundColor = background;
            titleBar.ForegroundColor = Colors.White;
            titleBar.ButtonBackgroundColor = background;
            titleBar.ButtonForegroundColor = Colors.White;
            titleBar.ButtonHoverBackgroundColor =
                ColorHelper.FromArgb(255, 22, 55, 83);
            titleBar.ButtonHoverForegroundColor = Colors.White;
            titleBar.ButtonPressedBackgroundColor =
                ColorHelper.FromArgb(255, 28, 76, 111);
            titleBar.ButtonPressedForegroundColor = Colors.White;
            titleBar.InactiveBackgroundColor = background;
            titleBar.InactiveForegroundColor = ColorHelper.FromArgb(255, 174, 194, 214);
            titleBar.ButtonInactiveBackgroundColor = background;
            titleBar.ButtonInactiveForegroundColor = ColorHelper.FromArgb(255, 174, 194, 214);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Guardian title bar theme could not be applied: {ex.Message}");
        }
    }

    // ==========================================
    // NAVIGATION
    // ==========================================

    private void RootNavigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer is not NavigationViewItem item)
            return;

        string section = item.Tag?.ToString() ?? "Dashboard";

        DashboardContent.Visibility = Visibility.Collapsed;
        VisionContent.Visibility = Visibility.Collapsed;
        SettingsContent.Visibility = Visibility.Collapsed;
        ModuleFrame.Visibility = Visibility.Collapsed;

        switch (section)
        {
            case "Dashboard":
                DashboardContent.Visibility = Visibility.Visible;
                break;

            case "Vision":
                VisionContent.Visibility = Visibility.Visible;
                break;

            case "Settings":
                SettingsContent.Visibility = Visibility.Visible;
                break;

            case "Author":
                ModuleFrame.Visibility = Visibility.Visible;
                ModuleFrame.Navigate(typeof(AuthorPage));
                break;

            case "Endpoint":
            case "Domain":
            case "Alerts":
            case "History":
                ModuleFrame.Visibility = Visibility.Visible;
                ModuleFrame.Navigate(typeof(ModulePage), section);
                break;
        }

        Debug.WriteLine($"Guardian navigation: {section}");
    }

    private void OpenAuthorButton_Click(object sender, RoutedEventArgs e)
    {
        var authorItem = RootNavigation.FooterMenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(item => string.Equals(
                item.Tag?.ToString(), "Author", StringComparison.Ordinal));

        if (authorItem != null)
            RootNavigation.SelectedItem = authorItem;
    }

    private void OpenHistoryButton_Click(object sender, RoutedEventArgs e)
    {
        var historyItem = RootNavigation.MenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(item => string.Equals(
                item.Tag?.ToString(), "History", StringComparison.Ordinal));

        if (historyItem != null)
            RootNavigation.SelectedItem = historyItem;
    }

    // ==========================================
    // WINDOW MANAGEMENT
    // ==========================================

    private void ShowGuardianWindow()
    {
        AppWindow.Show();

        Activate();
    }

    // ==========================================
    // ENDPOINT MONITORING
    // ==========================================

    private void RefreshData()
    {
        try
        {
            var snapshot = _telemetry.GetSnapshot();

            ProcessesText.Text =
                snapshot.Processes.ToString("N0");

            ConnectionsText.Text =
                snapshot.Connections.ToString("N0");

            AlertsText.Text =
                snapshot.Alerts.ToString("N0");

            LatestEventText.Text =
                snapshot.LastEvent;

            UpdatedText.Text =
                $"Updated: {DateTime.Now:HH:mm:ss}";

            RefreshRecentActivity(snapshot.RecentEvents);

            EngineStatusMiniText.Text =
                snapshot.ServiceStatus == "Running" ? "Running" : "Starting";

            EngineStatusMiniText.Foreground = new SolidColorBrush(
                snapshot.ServiceStatus == "Running"
                    ? ColorHelper.FromArgb(255, 91, 231, 164)
                    : ColorHelper.FromArgb(255, 255, 190, 104));

            UptimeText.Text = FormatUptime(DateTimeOffset.UtcNow - _startedAtUtc);

            if (snapshot.ServiceStatus == "Running")
            {
                StatusText.Text =
                    "Monitoring active";

                StatusText.Foreground =
                    new SolidColorBrush(
                        Colors.LightGreen);

                StatusDescription.Text =
                    "Guardian endpoint monitoring engine is running. " +
                    "Detection only; no automatic blocking.";
            }
            else
            {
                StatusText.Text =
                    "Monitoring starting";

                StatusText.Foreground =
                    new SolidColorBrush(
                        Colors.Orange);

                StatusDescription.Text =
                    "Waiting for monitoring initialization.";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text =
                "Monitoring unavailable";

            StatusText.Foreground =
                new SolidColorBrush(
                    Colors.OrangeRed);

            StatusDescription.Text =
                ex.Message;

            Debug.WriteLine(
                $"Guardian telemetry error: {ex}");
        }
    }

    private void RefreshRecentActivity(
        IReadOnlyList<TelemetryEventSnapshot>? events)
    {
        var recent = events?.Take(5).ToArray() ?? Array.Empty<TelemetryEventSnapshot>();
        string fingerprint = string.Join("|", recent.Select(item =>
            $"{item.Timestamp.UtcDateTime.Ticks}:{item.Category}:{item.Message}"));

        if (string.Equals(fingerprint, _lastActivityFingerprint, StringComparison.Ordinal))
            return;

        _lastActivityFingerprint = fingerprint;
        RecentActivityPanel.Children.Clear();

        if (recent.Length == 0)
        {
            RecentActivityPanel.Children.Add(new TextBlock
            {
                Text = "No endpoint events recorded yet.",
                FontSize = 13,
                Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 151, 180, 207)),
                Margin = new Thickness(0, 12, 0, 12),
                TextWrapping = TextWrapping.Wrap
            });
            return;
        }

        foreach (var item in recent)
        {
            var row = new Grid
            {
                ColumnSpacing = 12,
                Margin = new Thickness(0, 8, 0, 8)
            };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(91) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            Windows.UI.Color dotColor = item.Category switch
            {
                "ALERT" => ColorHelper.FromArgb(255, 255, 174, 105),
                "TCP" => ColorHelper.FromArgb(255, 63, 211, 238),
                _ => ColorHelper.FromArgb(255, 75, 225, 163)
            };

            var timePanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                VerticalAlignment = VerticalAlignment.Center
            };
            timePanel.Children.Add(new Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = new SolidColorBrush(dotColor),
                VerticalAlignment = VerticalAlignment.Center
            });
            timePanel.Children.Add(new TextBlock
            {
                Text = item.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
                FontSize = 11,
                Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 163, 194, 220)),
                VerticalAlignment = VerticalAlignment.Center
            });

            var message = new TextBlock
            {
                Text = item.Message,
                FontSize = 12,
                Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 226, 238, 249)),
                TextWrapping = TextWrapping.Wrap,
                MaxLines = 2,
                VerticalAlignment = VerticalAlignment.Center
            };

            Grid.SetColumn(timePanel, 0);
            Grid.SetColumn(message, 1);
            row.Children.Add(timePanel);
            row.Children.Add(message);
            RecentActivityPanel.Children.Add(row);

            if (!ReferenceEquals(item, recent[^1]))
            {
                RecentActivityPanel.Children.Add(new Border
                {
                    Height = 1,
                    Background = new SolidColorBrush(ColorHelper.FromArgb(255, 31, 62, 88)),
                    Margin = new Thickness(0, 2, 0, 2)
                });
            }
        }
    }

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime.TotalHours >= 1)
            return $"{(int)uptime.TotalHours:00}:{uptime.Minutes:00}:{uptime.Seconds:00}";

        return $"{uptime.Minutes:00}:{uptime.Seconds:00}";
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        RefreshData();
    }

    // ==========================================
    // INFORMATION DIALOGS
    // ==========================================

    private async void EndpointInfoButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (Content is FrameworkElement root)
        {
            await GuardianHelp.ShowEndpointAsync(
                root.XamlRoot);
        }
    }

    private async void VisionInfoButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (Content is FrameworkElement root)
        {
            await GuardianHelp.ShowVisionAsync(
                root.XamlRoot);
        }
    }

    private async void NotificationInfoButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (Content is not FrameworkElement root)
            return;

        var dialog = new ContentDialog
        {
            XamlRoot = root.XamlRoot,

            Title = "Security Notifications",

            Content =
                "GUARDIAN SECURITY NOTIFICATIONS\n\n" +

                "Guardian sends Windows notifications when " +
                "Vision detects HIGH or CRITICAL risk indicators.\n\n" +

                "LOW (0-19): No significant suspicious indicators.\n" +
                "MEDIUM (20-39): Potentially suspicious characteristics.\n" +
                "HIGH (40-69): Suspicious indicators detected.\n" +
                "CRITICAL (70-100): Multiple strong indicators detected.\n\n" +

                "Repeated alerts for the same domain and risk " +
                "level are limited to one notification every " +
                "10 minutes.\n\n" +

                "Use Send test notification to verify Windows alerts.\n\n" +

                "Guardian currently uses heuristic detection. " +
                "A high score is not proof of phishing.",

            CloseButtonText = "Close"
        };

        await dialog.ShowAsync();
    }

    // ==========================================
    // CONTINUOUS MONITORING HEALTH
    // ==========================================

    private void RefreshContinuousMonitoringStatus()
    {
        if (!_continuousMonitor.IsRunning)
            return;

        DateTime? lastFrame =
            _continuousMonitor.LastFrameReceivedUtc;

        DateTime? lastAnalysis =
            _continuousMonitor.LastAnalysisCompletedUtc;

        if (!lastFrame.HasValue)
        {
            ContinuousVisionStatusText.Text =
                "Waiting for first capture frame...";

            return;
        }

        TimeSpan frameAge =
            DateTime.UtcNow - lastFrame.Value;

        string analysisTime =
            lastAnalysis.HasValue
                ? lastAnalysis.Value
                    .ToLocalTime()
                    .ToString("HH:mm:ss")
                : "Pending";

        if (frameAge.TotalSeconds > 15)
        {
            ContinuousVisionStatusText.Text =
                $"No recent frames · Last analysis: {analysisTime}";

            VisionStatusText.Text =
                "Live assessment may be outdated";

            VisionStatusText.Foreground =
                new SolidColorBrush(
                    Colors.Orange);

            return;
        }

        ContinuousVisionStatusText.Text =
            $"Capture active · Last analysis: {analysisTime}";
    }

    // ==========================================
    // MANUAL SCREEN ANALYSIS
    // ==========================================

    private async void AnalyzeScreenButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_visionBusy ||
            _continuousStarting ||
            _continuousMonitor.IsRunning)
        {
            return;
        }

        _visionBusy = true;

        Button? button =
            sender as Button;

        if (button != null)
            button.IsEnabled = false;

        try
        {
            VisionStatusText.Text =
                "Select a browser window...";

            using SoftwareBitmap? bitmap =
                await _screenCapture.CaptureSingleFrameAsync(
                    this);

            if (bitmap == null)
            {
                VisionStatusText.Text =
                    "Capture cancelled";

                return;
            }

            VisionStatusText.Text =
                "Reading browser address...";

            var address =
                await _browserAddressReader.ReadAsync(
                    _screenCapture.LastCapturedWindowTitle);

            VisionStatusText.Text =
                "Running local OCR...";

            _textRecognizer ??=
                new ScreenTextRecognizer();

            string ocr =
                await _textRecognizer.RecognizeAsync(bitmap);

            var report = BuildReport(
                "Manual capture",
                address,
                ocr);

            PublishReport(report);
        }
        catch (Exception ex)
        {
            DisplayVisionError(ex);
        }
        finally
        {
            _visionBusy = false;

            if (button != null)
                button.IsEnabled = true;
        }
    }

    // ==========================================
    // CONTINUOUS VISION START / STOP
    // ==========================================

    private async void ContinuousVisionButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_continuousStarting || _visionBusy)
            return;

        _continuousStarting = true;

        ContinuousVisionButton.IsEnabled = false;

        try
        {
            // STOP.
            if (_continuousMonitor.IsRunning)
            {
                ContinuousVisionStatusText.Text =
                    "Stopping monitoring...";

                await _continuousMonitor.StopAsync();

                _lastContinuousFingerprint = null;

                ContinuousVisionButton.Content =
                    "Start continuous monitoring";

                ContinuousVisionButton.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 36, 122, 104));

                ContinuousVisionStatusText.Text =
                    "Continuous monitoring stopped";

                VisionStatusText.Text =
                    "Monitoring stopped - last assessment";

                VisionStatusText.Foreground =
                    new SolidColorBrush(
                        Colors.Orange);

                return;
            }

            // START.
            _lastContinuousFingerprint = null;

            ContinuousVisionStatusText.Text =
                "Select a browser window...";

            bool started =
                await _continuousMonitor.StartAsync(
                    this,
                    AnalyzeContinuousFrameAsync);

            if (!started)
            {
                ContinuousVisionStatusText.Text =
                    "Window selection cancelled";

                return;
            }

            ContinuousVisionButton.Content =
                "Stop continuous monitoring";

            ContinuousVisionButton.Background =
                new SolidColorBrush(
                    ColorHelper.FromArgb(
                        255, 145, 60, 55));

            ContinuousVisionStatusText.Text =
                "Continuous monitoring active";

            VisionStatusText.Text =
                "Waiting for live assessment...";

            VisionStatusText.Foreground =
                new SolidColorBrush(
                    Colors.Orange);
        }
        catch (Exception ex)
        {
            ContinuousVisionStatusText.Text =
                $"Monitoring error: {ex.Message}";

            Debug.WriteLine(
                $"Guardian continuous monitoring error: {ex}");
        }
        finally
        {
            _continuousStarting = false;

            ContinuousVisionButton.IsEnabled = true;
        }
    }

    // ==========================================
    // CONTINUOUS FRAME DISPATCH
    // ==========================================

    private Task AnalyzeContinuousFrameAsync(
        SoftwareBitmap bitmap)
    {
        var completion =
            new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);

        bool queued = DispatcherQueue.TryEnqueue(async () =>
        {
            try
            {
                if (_continuousMonitor.IsRunning)
                {
                    await AnalyzeContinuousFrameOnUiAsync(
                        bitmap);
                }

                completion.TrySetResult(true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"Guardian continuous frame error: {ex}");

                completion.TrySetException(ex);
            }
        });

        if (!queued)
        {
            completion.TrySetException(
                new InvalidOperationException(
                    "Guardian UI dispatcher unavailable."));
        }

        return completion.Task;
    }

    // ==========================================
    // CONTINUOUS FRAME ANALYSIS
    // ==========================================

    private async Task AnalyzeContinuousFrameOnUiAsync(
        SoftwareBitmap bitmap)
    {
        var address =
            await _browserAddressReader.ReadAsync(
                _continuousMonitor.SelectedWindowTitle);

        if (!_continuousMonitor.IsRunning)
            return;

        if (!address.Success ||
            string.IsNullOrWhiteSpace(address.Url))
        {
            SetUnknownAssessment(
                "Browser address could not be verified.");

            _lastContinuousFingerprint = null;

            return;
        }

        _textRecognizer ??=
            new ScreenTextRecognizer();

        string ocr =
            await _textRecognizer.RecognizeAsync(bitmap);

        if (!_continuousMonitor.IsRunning)
            return;

        string fingerprint =
            address.Url + "|" + ocr;

        if (fingerprint == _lastContinuousFingerprint)
            return;

        _lastContinuousFingerprint = fingerprint;

        var report = BuildReport(
            "Continuous monitoring",
            address,
            ocr);

        PublishReport(report);
    }

    // ==========================================
    // BUILD ANALYSIS REPORT
    // ==========================================

    private AnalysisReport BuildReport(
        string source,
        BrowserAddressResult address,
        string ocrText)
    {
        var ocrUrls =
            _urlExtractor.Extract(ocrText);

        string domain = "Unknown";

        if (Uri.TryCreate(
            address.Url,
            UriKind.Absolute,
            out Uri? uri))
        {
            domain = uri.IdnHost;
        }

        // Unverified address.
        if (!address.Success ||
            string.IsNullOrWhiteSpace(address.Url))
        {
            return new AnalysisReport(
                DateTime.Now,
                source,
                address.Browser,
                domain,
                null,
                ocrUrls.ToArray(),
                "UNKNOWN",
                null,
                "Browser address unavailable. " +
                "A reliable risk assessment could not be performed.",
                new[]
                {
                    address.Message
                },
                ocrText);
        }

        // Empty OCR.
        if (string.IsNullOrWhiteSpace(ocrText))
        {
            return new AnalysisReport(
                DateTime.Now,
                source,
                address.Browser,
                domain,
                address.Url,
                ocrUrls.ToArray(),
                "UNKNOWN",
                null,
                "No readable page content was detected.",
                new[]
                {
                    "OCR returned no readable text."
                },
                ocrText);
        }

        // Heuristic analysis.
        var result =
            _phishingAnalyzer.Analyze(
                ocrText,
                new[] { address.Url });

        return new AnalysisReport(
            DateTime.Now,
            source,
            address.Browser,
            domain,
            address.Url,
            ocrUrls.ToArray(),
            result.RiskLevel,
            result.Score,
            result.Summary,
            result.Reasons.ToArray(),
            ocrText);
    }

    // ==========================================
    // PUBLISH ANALYSIS
    // ==========================================

    private void PublishReport(AnalysisReport report)
    {
        _latestReport = report;

        _historyStore.Save(report);

        VisionAiVerdictText.Text = "Not analyzed";
        CloudAiButton.IsEnabled =
            _cloudClient.IsConfigured &&
            !string.IsNullOrWhiteSpace(report.ActiveUrl) &&
            !string.IsNullOrWhiteSpace(report.RecognizedText);

        CloudAiStatusText.Text = _cloudClient.IsConfigured
            ? "Local analysis complete · Claude is optional. Click Analyze latest page with Claude to request cloud analysis."
            : "Cloud token not configured · local analysis is still available.";

        _sessionHistory.Add(report);

        // Keep session history limited.
        if (_sessionHistory.Count > 50)
            _sessionHistory.RemoveAt(0);

        VisionDomainText.Text =
            report.Domain;

        VisionScoreText.Text =
            report.RiskScore.HasValue
                ? $"{report.RiskScore.Value}/100"
                : "--/100";

        VisionSummaryText.Text =
            report.Summary +
            "\n\nPreliminary heuristic assessment. " +
            "A low score does not guarantee safety.";

        UpdateRiskPresentation(
            report.RiskLevel);

        VisionDetailsButton.IsEnabled = true;

        // Send Windows notifications.
        if (report.RiskLevel == "HIGH" ||
            report.RiskLevel == "CRITICAL")
        {
            _latestAlertReport = report;

            bool sent =
                _notifications.SendThreatNotification(
                    report);

            if (sent)
            {
                Debug.WriteLine(
                    $"Guardian alert sent: {report.Domain} " +
                    $"({report.RiskLevel})");
            }
        }
    }

    // ==========================================
    // RISK PRESENTATION
    // ==========================================

    private void UpdateRiskPresentation(
        string riskLevel)
    {
        VisionRiskBadgeText.Text =
            riskLevel;

        switch (riskLevel)
        {
            case "CRITICAL":

                SetRiskAppearance(
                    "Critical suspicious indicators",
                    155, 42, 52,
                    Colors.OrangeRed);

                break;

            case "HIGH":

                SetRiskAppearance(
                    "Suspicious website indicators",
                    155, 73, 36,
                    Colors.Orange);

                break;

            case "MEDIUM":

                SetRiskAppearance(
                    "Potentially suspicious content",
                    135, 107, 38,
                    Colors.Orange);

                break;

            case "LOW":

                SetRiskAppearance(
                    "No suspicious indicators detected",
                    31, 111, 82,
                    Colors.LightGreen);

                break;

            default:

                SetRiskAppearance(
                    "Analysis unavailable",
                    68, 80, 99,
                    Colors.Orange);

                break;
        }
    }

    private void SetRiskAppearance(
        string status,
        byte r,
        byte g,
        byte b,
        Windows.UI.Color foreground)
    {
        VisionStatusText.Text =
            status;

        VisionStatusText.Foreground =
            new SolidColorBrush(foreground);

        VisionRiskBadge.Background =
            new SolidColorBrush(
                ColorHelper.FromArgb(
                    255, r, g, b));
    }

    // ==========================================
    // OPTIONAL CLAUDE CLOUD ANALYSIS
    // ==========================================

    private async void CloudAiButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_cloudBusy || _latestReport == null)
            return;

        if (!_cloudClient.IsConfigured)
        {
            CloudAiStatusText.Text =
                "Cloud access token is missing. Run Scripts\\Setup-GuardianCloudToken.ps1.";
            return;
        }

        if (string.IsNullOrWhiteSpace(_latestReport.ActiveUrl) ||
            string.IsNullOrWhiteSpace(_latestReport.RecognizedText))
        {
            CloudAiStatusText.Text =
                "A verified browser URL and recognized page text are required.";
            return;
        }

        _cloudBusy = true;
        CloudAiButton.IsEnabled = false;
        CloudAiButton.Content = "Analyzing with Claude...";
        CloudAiStatusText.Text =
            "Sending verified URL, OCR text and local findings to Guardian Cloud. No screenshot is uploaded.";
        VisionAiVerdictText.Text = "Analysis in progress...";

        try
        {
            using var timeout = new System.Threading.CancellationTokenSource(
                TimeSpan.FromSeconds(50));

            AnalysisReport sourceReport = _latestReport;
            GuardianCloudEnvelope response = await _cloudClient.AnalyzeAsync(
                sourceReport,
                timeout.Token);

            AnalysisReport updatedReport = sourceReport with
            {
                CloudAnalysis = response.Analysis,
                CloudUsage = response.Usage,
                CloudModel = response.Model,
                CloudAnalyzedAt = response.Timestamp ?? DateTimeOffset.UtcNow
            };

            _latestReport = updatedReport;
            _historyStore.Save(updatedReport);

            int sessionIndex = _sessionHistory.FindIndex(item => item.Id == sourceReport.Id);
            if (sessionIndex >= 0)
                _sessionHistory[sessionIndex] = updatedReport;

            var ai = response.Analysis!;
            VisionAiVerdictText.Text =
                $"{ai.Verdict} · {ai.Confidence}% confidence";

            string usageText = response.Usage == null
                ? ""
                : $" · {response.Usage.InputTokens:N0} in / {response.Usage.OutputTokens:N0} out";

            string domainStatus = ai.DomainAssessment is { } domain
                ? domain.Status == "MATCHED_KNOWN_OFFICIAL_DOMAIN"
                    ? $" · Domain registry: {domain.Brand} match ({domain.OfficialDomain})"
                    : $" · No known registry match for {domain.Hostname}"
                : string.Empty;

            CloudAiStatusText.Text =
                $"Claude analysis completed · {response.Model}{usageText}{domainStatus}";

            if ((ai.Verdict == "HIGH" || ai.Verdict == "CRITICAL") &&
                ai.Confidence >= 75)
            {
                _latestAlertReport = updatedReport;
                _notifications.SendAiThreatNotification(updatedReport);
            }

            Debug.WriteLine(
                $"Guardian Cloud analysis completed for {sourceReport.Domain}: {ai.Verdict} ({ai.Confidence}%).");
        }
        catch (GuardianCloudException ex)
        {
            VisionAiVerdictText.Text = "Cloud analysis unavailable";
            CloudAiStatusText.Text = ex.Message;
            Debug.WriteLine($"Guardian Cloud error: {ex.Message}");
        }
        catch (OperationCanceledException)
        {
            VisionAiVerdictText.Text = "Analysis timed out";
            CloudAiStatusText.Text =
                "Claude did not respond in time. Local heuristic results remain available.";
        }
        catch (Exception ex)
        {
            VisionAiVerdictText.Text = "Cloud analysis failed";
            CloudAiStatusText.Text =
                "Cloud analysis failed. Local heuristic results remain available.";
            Debug.WriteLine($"Guardian Cloud unexpected error: {ex}");
        }
        finally
        {
            _cloudBusy = false;
            CloudAiButton.Content = "Analyze latest page with Claude";
            CloudAiButton.IsEnabled =
                _latestReport != null &&
                _cloudClient.IsConfigured &&
                !string.IsNullOrWhiteSpace(_latestReport.ActiveUrl) &&
                !string.IsNullOrWhiteSpace(_latestReport.RecognizedText);
        }
    }

    // ==========================================
    // ANALYSIS DETAILS WINDOW
    // ==========================================

    private void VisionDetailsButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        OpenAnalysisDetails(_latestReport);
    }

    private void OpenAnalysisDetails(
        AnalysisReport? report)
    {
        if (report == null)
            return;

        try
        {
            _detailsWindow?.Close();

            var window =
                new AnalysisDetailsWindow(report);

            _detailsWindow = window;

            window.Closed += (_, _) =>
            {
                if (ReferenceEquals(
                    _detailsWindow, window))
                {
                    _detailsWindow = null;
                }
            };

            window.Activate();
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian report window error: {ex}");
        }
    }

    // ==========================================
    // TEST NOTIFICATION
    // ==========================================

    private void TestNotificationButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!_notifications.IsAvailable)
        {
            NotificationStatusText.Text =
                "Notification service unavailable.";

            return;
        }

        _latestAlertReport = new AnalysisReport(
            DateTime.Now,
            "Notification test",
            "Guardian",
            "127.0.0.1",
            "http://127.0.0.1/login",
            Array.Empty<string>(),
            "HIGH",
            45,
            "Synthetic test alert - no real threat detected.",
            new[]
            {
                "+20: Local IP address used as website host.",
                "+25: Login context over HTTP."
            },
            "Synthetic test content. No screenshot captured.");

        bool sent =
            _notifications.SendTestNotification();

        NotificationStatusText.Text =
            sent
                ? "Test notification submitted to Windows."
                : "Could not submit test notification.";
    }

    // ==========================================
    // UNKNOWN ASSESSMENT
    // ==========================================

    private void SetUnknownAssessment(
        string message)
    {
        VisionDomainText.Text =
            "Address unavailable";

        VisionScoreText.Text =
            "--/100";

        UpdateRiskPresentation("UNKNOWN");

        VisionSummaryText.Text =
            message;

        _latestReport = null;

        VisionDetailsButton.IsEnabled = false;
    }

    // ==========================================
    // VISION ERROR HANDLING
    // ==========================================

    private void DisplayVisionError(Exception ex)
    {
        Debug.WriteLine(
            $"Guardian Vision error: {ex}");

        SetUnknownAssessment(
            "Analysis failed: " + ex.Message);
    }

    // ==========================================
    // APPLICATION SHUTDOWN
    // ==========================================

    private void OnWindowClosed(
        object sender,
        WindowEventArgs args)
    {
        _refreshTimer?.Stop();

        _windowManager.IsVisibleInTray = false;

        _windowManager.Dispose();

        _notifications.Dispose();
    }
}
