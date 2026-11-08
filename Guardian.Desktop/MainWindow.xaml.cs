
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Guardian.Desktop.Notifications;
using Guardian.Desktop.Pages;
using Guardian.Desktop.UI;
using Guardian.Desktop.Vision;
using Guardian.Service.IPC;

using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

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

    private bool _continuousStarting;

    private bool _allowClose;

    private string? _lastContinuousFingerprint;

    // ==========================================
    // CONSTRUCTOR
    // ==========================================

    public MainWindow(TelemetryState telemetry)
    {
        InitializeComponent();

        _telemetry = telemetry;

        Title = "Guardian";

        // Premium desktop window.
        AppWindow.Resize(new SizeInt32(1120, 720));

        // ======================================
        // GUARDIAN APPLICATION ICON
        // ======================================

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
            Debug.WriteLine(
                $"Guardian icon not found: {iconPath}");
        }

        // ======================================
        // INITIAL DASHBOARD STATE
        // ======================================

        DashboardContent.Visibility =
            Visibility.Visible;

        ModuleFrame.Visibility =
            Visibility.Collapsed;

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

                    _refreshTimer.Stop();

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

        // ======================================
        // INITIAL ENDPOINT STATE
        // ======================================

        RefreshData();

        Debug.WriteLine(
            "Guardian Premium Desktop initialized.");
    }

    // ==========================================
    // NAVIGATION
    // ==========================================

    private void RootNavigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer
            is not NavigationViewItem item)
        {
            return;
        }

        string section =
            item.Tag?.ToString() ?? "Dashboard";

        Debug.WriteLine(
            $"Guardian navigation: {section}");

        // Dashboard.
        if (section == "Dashboard")
        {
            DashboardContent.Visibility =
                Visibility.Visible;

            ModuleFrame.Visibility =
                Visibility.Collapsed;

            return;
        }

        // Other modules.
        DashboardContent.Visibility =
            Visibility.Collapsed;

        ModuleFrame.Visibility =
            Visibility.Visible;

        ModuleFrame.Navigate(
            typeof(ModulePage),
            section);
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
        _refreshTimer.Stop();

        _windowManager.IsVisibleInTray = false;

        _windowManager.Dispose();

        _notifications.Dispose();
    }
}
