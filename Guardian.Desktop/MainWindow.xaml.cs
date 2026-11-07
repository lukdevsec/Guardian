
using System;
using System.Linq;

using Guardian.Service.IPC;
using Guardian.Desktop.Vision;

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
    private readonly TelemetryState _telemetry;

    private readonly BrowserAddressReader _browserAddressReader = new();

    private readonly DispatcherTimer _refreshTimer;

    private readonly WindowManager _windowManager;

    private readonly ScreenCaptureManager _screenCapture = new();

    private readonly UrlExtractor _urlExtractor = new();

    private readonly PhishingAnalyzer _phishingAnalyzer = new();

    private ScreenTextRecognizer? _textRecognizer;

    private bool _visionBusy;
    private bool _visionDetailsExpanded;
    private bool _allowClose;

    public MainWindow(TelemetryState telemetry)
    {
        InitializeComponent();

        _telemetry = telemetry;

        // Window configuration.
        AppWindow.Resize(new SizeInt32(390, 710));

        // System tray.
        _windowManager = WindowManager.Get(this);

        _windowManager.IsVisibleInTray = true;

        _windowManager.TrayIconSelected += (_, _) =>
        {
            ShowGuardianWindow();
        };

        // Tray context menu.
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
                _allowClose = true;
                _refreshTimer.Stop();

                _windowManager.IsVisibleInTray = false;

                await ((App)Application.Current)
                    .ShutdownAsync();
            };

            menu.Items.Add(openItem);
            menu.Items.Add(new MenuFlyoutSeparator());
            menu.Items.Add(exitItem);

            e.Flyout = menu;
        };

        // X hides the window instead of exiting.
        AppWindow.Closing += (_, e) =>
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                AppWindow.Hide();
            }
        };

        PositionBottomRight();

        // Live telemetry refresh.
        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };

        _refreshTimer.Tick += (_, _) =>
        {
            RefreshData();
        };

        _refreshTimer.Start();

        Closed += OnWindowClosed;

        RefreshData();

        // Initial Vision state.
        VisionStatusText.Text = "Screen analysis inactive";
        VisionDomainText.Text = "No website analyzed";

        VisionRiskBadgeText.Text = "NOT ANALYZED";
        VisionScoreText.Text = "--/100";

        VisionSummaryText.Text =
            "Waiting for website analysis.";

        VisionUrlsText.Text = "No URLs detected.";
        VisionReasonsText.Text = "No analysis available.";
        VisionOcrText.Text = "No OCR data.";

        VisionDetailsButton.IsEnabled = false;

        VisionDetailsPanel.Visibility =
            Visibility.Collapsed;
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

            var workArea = displayArea.WorkArea;
            var size = AppWindow.Size;

            int x = workArea.X +
                    workArea.Width -
                    size.Width - 16;

            int y = workArea.Y +
                    workArea.Height -
                    size.Height - 16;

            AppWindow.Move(new PointInt32(
                Math.Max(workArea.X, x),
                Math.Max(workArea.Y, y)));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"Guardian positioning error: {ex.Message}");
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
                $"Live update: {DateTime.Now:HH:mm:ss}";

            if (snapshot.ServiceStatus == "Running")
            {
                StatusText.Text = "Monitoring active";

                StatusText.Foreground =
                    new SolidColorBrush(Colors.LightGreen);

                StatusDescription.Text =
                    "Guardian monitoring engine is running. " +
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
            StatusText.Text = "Monitoring unavailable";

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
    // VISION DETAILS
    // ==========================================

    private void VisionDetailsButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        _visionDetailsExpanded =
            !_visionDetailsExpanded;

        VisionDetailsPanel.Visibility =
            _visionDetailsExpanded
                ? Visibility.Visible
                : Visibility.Collapsed;

        VisionDetailsButton.Content =
            _visionDetailsExpanded
                ? "Hide analysis details"
                : "View analysis details";
    }

    // ==========================================
    // RISK PRESENTATION
    // ==========================================

    private void UpdateRiskPresentation(
        string riskLevel)
    {
        switch (riskLevel)
        {
            case "CRITICAL":

                VisionRiskBadge.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 125, 35, 42));

                VisionStatusText.Text =
                    "Critical threat indicators detected";

                VisionStatusText.Foreground =
                    new SolidColorBrush(Colors.OrangeRed);

                break;

            case "HIGH":

                VisionRiskBadge.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 125, 65, 35));

                VisionStatusText.Text =
                    "Suspicious website indicators";

                VisionStatusText.Foreground =
                    new SolidColorBrush(Colors.Orange);

                break;

            case "MEDIUM":

                VisionRiskBadge.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 115, 95, 40));

                VisionStatusText.Text =
                    "Potentially suspicious content";

                VisionStatusText.Foreground =
                    new SolidColorBrush(Colors.Orange);

                break;

            case "LOW":

                VisionRiskBadge.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 35, 105, 78));

                VisionStatusText.Text =
                    "No suspicious indicators detected";

                VisionStatusText.Foreground =
                    new SolidColorBrush(Colors.LightGreen);

                break;

            default:

                VisionRiskBadge.Background =
                    new SolidColorBrush(
                        ColorHelper.FromArgb(
                            255, 65, 75, 90));

                VisionStatusText.Text =
                    "Analysis incomplete";

                VisionStatusText.Foreground =
                    new SolidColorBrush(Colors.Orange);

                break;
        }

        VisionRiskBadgeText.Text = riskLevel;
    }

    // ==========================================
    // GUARDIAN VISION ANALYSIS
    // ==========================================


    private async void AnalyzeScreenButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_visionBusy)
            return;

        _visionBusy = true;

        Button? actionButton = sender as Button;

        if (actionButton != null)
            actionButton.IsEnabled = false;

        VisionDetailsPanel.Visibility = Visibility.Collapsed;
        _visionDetailsExpanded = false;

        VisionDetailsButton.Content = "View analysis details";
        VisionDetailsButton.IsEnabled = false;

        try
        {
            VisionStatusText.Text = "Waiting for selection...";
            VisionDomainText.Text = "Selecting browser...";
            VisionRiskBadgeText.Text = "ANALYZING";
            VisionScoreText.Text = "--/100";

            VisionSummaryText.Text = "Capturing browser window...";

            using SoftwareBitmap? bitmap =
                await _screenCapture.CaptureSingleFrameAsync(this);

            if (bitmap == null)
            {
                VisionStatusText.Text = "Capture cancelled";
                VisionDomainText.Text = "No website analyzed";
                VisionSummaryText.Text = "No window was selected.";

                UpdateRiskPresentation("UNKNOWN");
                return;
            }

            // 1. Read actual browser address using UI Automation.
            VisionStatusText.Text = "Reading browser address...";

            var browserAddress =
                await _browserAddressReader.ReadAsync(
                    _screenCapture.LastCapturedWindowTitle);

            // 2. OCR page content.
            VisionStatusText.Text = "Running local OCR...";

            _textRecognizer ??= new ScreenTextRecognizer();

            string extractedText =
                await _textRecognizer.RecognizeAsync(bitmap);

            // 3. Extract OCR URL candidates for reference only.
            var detectedUrls =
                _urlExtractor.Extract(extractedText);

            // 4. Only trust the browser address as the active URL.
            VisionDomainText.Text =
                browserAddress.Success &&
                Uri.TryCreate(
                    browserAddress.Url,
                    UriKind.Absolute,
                    out Uri? actualUri)
                    ? actualUri.IdnHost
                    : "Active address unavailable";

            if (!browserAddress.Success ||
                string.IsNullOrWhiteSpace(browserAddress.Url))
            {
                VisionStatusText.Text =
                    "Address could not be verified";

                VisionRiskBadgeText.Text = "UNKNOWN";
                VisionScoreText.Text = "--/100";

                VisionSummaryText.Text =
                    browserAddress.Message +
                    "\n\nOCR URL candidates are not treated as the active website address.";

                VisionUrlsText.Text =
                    "BROWSER ADDRESS:\nUnavailable\n\n" +
                    "OCR URL CANDIDATES (unverified):\n" +
                    (detectedUrls.Count == 0
                        ? "None detected."
                        : string.Join(
                            Environment.NewLine,
                            detectedUrls));

                VisionReasonsText.Text =
                    "A reliable active browser address was not available. " +
                    "Domain-based phishing assessment was skipped.";

                VisionOcrText.Text =
                    LimitText(extractedText, 5000);

                UpdateRiskPresentation("UNKNOWN");

                VisionDetailsButton.IsEnabled = true;

                return;
            }

            // 5. Analyze ONLY the actual browser address.
            var result = _phishingAnalyzer.Analyze(
                extractedText,
                new[] { browserAddress.Url });

            VisionUrlsText.Text =
                "ACTIVE BROWSER ADDRESS (UI AUTOMATION):\n" +
                browserAddress.Url +
                "\n\nOCR URL CANDIDATES (unverified):\n" +
                (detectedUrls.Count == 0
                    ? "None detected."
                    : string.Join(
                        Environment.NewLine,
                        detectedUrls));

            // 6. Risk assessment.
            VisionScoreText.Text =
                $"{result.Score}/100";

            VisionSummaryText.Text =
                result.Summary +
                "\n\nSource: browser address bar + local OCR." +
                "\nHeuristic screening only; not a safety guarantee.";

            UpdateRiskPresentation(result.RiskLevel);

            // 7. Detailed reasons.
            VisionReasonsText.Text =
                result.Reasons.Count == 0
                    ? "No suspicious indicators detected by current rules."
                    : string.Join(
                        Environment.NewLine,
                        result.Reasons.Select(
                            reason => "• " + reason));

            VisionOcrText.Text =
                LimitText(extractedText, 5000);

            VisionDetailsButton.IsEnabled = true;

            System.Diagnostics.Debug.WriteLine(
                $"Guardian browser: {browserAddress.Browser} | " +
                $"URL: {browserAddress.Url} | " +
                $"Risk: {result.RiskLevel} | " +
                $"Score: {result.Score}/100");
        }
        catch (Exception ex)
        {
            VisionStatusText.Text = "Analysis failed";
            VisionDomainText.Text = "Analysis unavailable";

            VisionSummaryText.Text = ex.Message;

            UpdateRiskPresentation("UNKNOWN");

            System.Diagnostics.Debug.WriteLine(
                $"Guardian Vision error: {ex}");
        }
        finally
        {
            _visionBusy = false;

            if (actionButton != null)
                actionButton.IsEnabled = true;
        }
    }


    // ==========================================
    // TEXT HELPERS
    // ==========================================

    private static string LimitText(
        string text,
        int maxLength)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "No readable text detected.";

        if (text.Length <= maxLength)
            return text;

        return text[..maxLength] +
               "\n\n[Output truncated]";
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
    }
}
