
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using Guardian.Desktop.UI;

using Guardian.Desktop.Notifications;
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
    // CORE

    private readonly TelemetryState _telemetry;
    private readonly DispatcherTimer _refreshTimer;
    private readonly WindowManager _windowManager;

    // VISION

    private readonly ScreenCaptureManager _screenCapture = new();
    private readonly ContinuousScreenMonitor _continuousMonitor = new();
    private readonly BrowserAddressReader _browserAddressReader = new();
    private readonly UrlExtractor _urlExtractor = new();
    private readonly PhishingAnalyzer _phishingAnalyzer = new();


    private async void EndpointInfoButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (Content is FrameworkElement root)
        {
            await GuardianHelp.ShowEndpointAsync(root.XamlRoot);
        }
    }

    private async void VisionInfoButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (Content is FrameworkElement root)
        {
            await GuardianHelp.ShowVisionAsync(root.XamlRoot);
        }
    }


    private ScreenTextRecognizer? _textRecognizer;

    // NOTIFICATIONS

    private readonly NotificationService _notifications;

    // REPORTS

    private AnalysisReport? _latestReport;
    private AnalysisReport? _latestAlertReport;

    private AnalysisDetailsWindow? _detailsWindow;

    private readonly List<AnalysisReport> _sessionHistory = new();

    // STATE

    private bool _visionBusy;
    private bool _continuousStarting;
    private bool _allowClose;

    private string? _lastContinuousFingerprint;

    public MainWindow(TelemetryState telemetry)
    {
        InitializeComponent();
        string iconPath = Path.Combine(
    AppContext.BaseDirectory,
    "Assets",
    "GuardianIcon.ico");

        if (File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }

        _telemetry = telemetry;

        Title = "Guardian";
        AppWindow.Resize(new SizeInt32(390, 710));

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

            var open = new MenuFlyoutItem
            {
                Text = "Open Guardian"
            };

            open.Click += (_, _) => ShowGuardianWindow();

            var exit = new MenuFlyoutItem
            {
                Text = "Exit Guardian"
            };

            exit.Click += async (_, _) =>
            {
                try
                {
                    ContinuousVisionButton.IsEnabled = false;

                    await _continuousMonitor.StopAsync();

                    _allowClose = true;

                    _refreshTimer.Stop();

                    _notifications.Dispose();

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

            menu.Items.Add(open);
            menu.Items.Add(new MenuFlyoutSeparator());
            menu.Items.Add(exit);

            e.Flyout = menu;
        };

        AppWindow.Closing += (_, e) =>
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                AppWindow.Hide();
            }
        };

        PositionBottomRight();

        // ======================================
        // TELEMETRY
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
        // NOTIFICATIONS
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
                : "Notifications unavailable - check MSIX registration";

        // ======================================
        // INITIAL UI
        // ======================================

        ContinuousVisionButton.Content =
            "Start continuous monitoring";

        ContinuousVisionStatusText.Text =
            "Continuous monitoring inactive";

        VisionDetailsButton.IsEnabled = false;

        VisionStatusText.Text =
            "No website analyzed";

        VisionDomainText.Text =
            "No active website";

        VisionRiskBadgeText.Text =
            "UNKNOWN";

        VisionScoreText.Text = "--/100";

        VisionSummaryText.Text =
            "Start a screen analysis to view security findings.";

        RefreshData();
    }

    // ==========================================
    // WINDOW MANAGEMENT
    // ==========================================

    private void ShowGuardianWindow()
    {
        PositionBottomRight();

        AppWindow.Show();
        Activate();
    }

    private void PositionBottomRight()
    {
        try
        {
            var hwnd =
                WinRT.Interop.WindowNative.GetWindowHandle(this);

            var windowId =
                Win32Interop.GetWindowIdFromWindow(hwnd);

            var displayArea = DisplayArea.GetFromWindowId(
                windowId,
                DisplayAreaFallback.Nearest);

            if (displayArea == null)
                return;

            var area = displayArea.WorkArea;
            var size = AppWindow.Size;

            int x = area.X + area.Width - size.Width - 16;
            int y = area.Y + area.Height - size.Height - 16;

            AppWindow.Move(new PointInt32(
                Math.Max(area.X, x),
                Math.Max(area.Y, y)));
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian position error: {ex.Message}");
        }
    }

    // ==========================================
    // TELEMETRY
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
                StatusText.Text = "Monitoring active";

                StatusText.Foreground =
                    new SolidColorBrush(Colors.LightGreen);

                StatusDescription.Text =
                    "Process and network monitoring active. " +
                    "Detection only; no automatic blocking.";
            }
            else
            {
                StatusText.Text = "Monitoring starting";

                StatusText.Foreground =
                    new SolidColorBrush(Colors.Orange);

                StatusDescription.Text =
                    "Waiting for monitoring initialization.";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text =
                "Monitoring unavailable";

            StatusText.Foreground =
                new SolidColorBrush(Colors.OrangeRed);

            StatusDescription.Text = ex.Message;
        }
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        RefreshData();
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

        TimeSpan age =
            DateTime.UtcNow - lastFrame.Value;

        string last = lastAnalysis.HasValue
            ? lastAnalysis.Value.ToLocalTime()
                .ToString("HH:mm:ss")
            : "Pending";

        if (age.TotalSeconds > 15)
        {
            ContinuousVisionStatusText.Text =
                $"No recent frames · Last analysis: {last}";

            // An old LOW result must not appear current.
            VisionStatusText.Text =
                "Live assessment may be outdated";

            VisionStatusText.Foreground =
                new SolidColorBrush(Colors.Orange);

            return;
        }

        ContinuousVisionStatusText.Text =
            $"Capture active · Last analysis: {last}";
    }

    // ==========================================
    // MANUAL VISION
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

        Button? button = sender as Button;

        if (button != null)
            button.IsEnabled = false;

        try
        {
            VisionStatusText.Text =
                "Select a browser window...";

            using SoftwareBitmap? bitmap =
                await _screenCapture.CaptureSingleFrameAsync(this);

            if (bitmap == null)
            {
                VisionStatusText.Text =
                    "Capture cancelled";
                return;
            }

            VisionStatusText.Text =
                "Analyzing selected window...";

            var address = await _browserAddressReader.ReadAsync(
                _screenCapture.LastCapturedWindowTitle);

            _textRecognizer ??= new ScreenTextRecognizer();

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
                    new SolidColorBrush(Colors.Orange);

                return;
            }

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
                "Continuous monitoring started";

            VisionStatusText.Text =
                "Waiting for live assessment...";

            VisionStatusText.Foreground =
                new SolidColorBrush(Colors.Orange);
        }
        catch (Exception ex)
        {
            ContinuousVisionStatusText.Text =
                $"Monitoring error: {ex.Message}";

            Debug.WriteLine(ex);
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
                    await AnalyzeContinuousFrameOnUiAsync(bitmap);
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
                    "UI dispatcher unavailable."));
        }

        return completion.Task;
    }

    // ==========================================
    // CONTINUOUS ANALYSIS
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

        _textRecognizer ??= new ScreenTextRecognizer();

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
        var ocrUrls = _urlExtractor.Extract(ocrText);

        string domain = "Unknown";

        if (Uri.TryCreate(
            address.Url,
            UriKind.Absolute,
            out Uri? uri))
        {
            domain = uri.IdnHost;
        }

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

        var result = _phishingAnalyzer.Analyze(
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

        // Limit retained text data in memory.
        if (_sessionHistory.Count > 50)
            _sessionHistory.RemoveAt(0);

        VisionDomainText.Text = report.Domain;

        VisionScoreText.Text =
            report.RiskScore.HasValue
                ? $"{report.RiskScore.Value}/100"
                : "--/100";

        VisionSummaryText.Text =
            report.Summary +
            "\n\nPreliminary heuristic assessment.";

        UpdateRiskPresentation(report.RiskLevel);

        VisionDetailsButton.IsEnabled = true;

        if (report.RiskLevel == "HIGH" ||
            report.RiskLevel == "CRITICAL")
        {
            _latestAlertReport = report;

            bool sent =
                _notifications.SendThreatNotification(report);

            if (sent)
            {
                Debug.WriteLine(
                    $"Guardian security notification: " +
                    $"{report.Domain} ({report.RiskLevel})");
            }
        }
    }

    // ==========================================
    // RISK PRESENTATION
    // ==========================================

    private void UpdateRiskPresentation(
        string riskLevel)
    {
        VisionRiskBadgeText.Text = riskLevel;

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
        VisionStatusText.Text = status;

        VisionStatusText.Foreground =
            new SolidColorBrush(foreground);

        VisionRiskBadge.Background =
            new SolidColorBrush(
                ColorHelper.FromArgb(255, r, g, b));
    }

    // ==========================================
    // SEPARATE ANALYSIS WINDOW
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
            // Recreate the details window for the selected
            // report so that its content is always consistent.
            _detailsWindow?.Close();

            var window =
                new AnalysisDetailsWindow(report);

            _detailsWindow = window;

            window.Closed += (_, _) =>
            {
                if (ReferenceEquals(_detailsWindow, window))
                    _detailsWindow = null;
            };

            window.Activate();
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian details window error: {ex}");
        }
    }

    // ==========================================
    // TEST WINDOWS NOTIFICATION
    // ==========================================

    private void TestNotificationButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!_notifications.IsAvailable)
        {
            NotificationStatusText.Text =
                "Notification service unavailable. Check MSIX manifest.";
            return;
        }

        // A synthetic report only.
        // No suspicious website is opened.
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
            "Synthetic test content. No screenshot was captured.");

        bool sent = _notifications.SendTestNotification();

        NotificationStatusText.Text = sent
            ? "Test notification submitted to Windows."
            : "Could not submit test notification.";
    }

    // ==========================================
    // UNKNOWN / ERRORS
    // ==========================================

    private void SetUnknownAssessment(
        string message)
    {
        VisionDomainText.Text = "Address unavailable";
        VisionScoreText.Text = "--/100";

        UpdateRiskPresentation("UNKNOWN");

        VisionSummaryText.Text = message;

        // Prevent opening an outdated report.
        _latestReport = null;
        VisionDetailsButton.IsEnabled = false;
    }

    private void DisplayVisionError(Exception ex)
    {
        Debug.WriteLine(
            $"Guardian Vision error: {ex}");

        SetUnknownAssessment(
            "Analysis failed: " + ex.Message);
    }

    // ==========================================
    // WINDOW CLOSED
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

                "Guardian automatically sends Windows notifications " +
                "when a website is classified as HIGH or CRITICAL risk.\n\n" +

                "RISK LEVELS\n\n" +
                "LOW (0-19): No significant suspicious indicators.\n" +
                "MEDIUM (20-39): Potentially suspicious characteristics.\n" +
                "HIGH (40-69): Suspicious indicators detected.\n" +
                "CRITICAL (70-100): Multiple strong indicators detected.\n\n" +

                "WHEN WILL I RECEIVE A NOTIFICATION?\n\n" +
                "When Guardian Vision detects a new HIGH or CRITICAL " +
                "assessment during manual or continuous analysis.\n\n" +

                "To prevent notification spam, Guardian limits repeated " +
                "alerts for the same domain and risk level to one " +
                "notification every 10 minutes.\n\n" +

                "TESTING\n\n" +
                "Click 'Send test notification' to safely verify " +
                "that Windows notifications are working.\n\n" +

                "IMPORTANT\n\n" +
                "Guardian currently uses heuristic detection rules. " +
                "A high score is not proof of phishing, and a low " +
                "score does not guarantee website safety.",

            CloseButtonText = "Close"
        };

        await dialog.ShowAsync();
    }

}
