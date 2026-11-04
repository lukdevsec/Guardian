
using System;
using Guardian.Service.IPC;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using WinUIEx;

namespace Guardian.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly TelemetryState _telemetry;
    private readonly DispatcherTimer _refreshTimer;
    private readonly WindowManager _windowManager;

    private bool _allowClose;

    public MainWindow(TelemetryState telemetry)
    {
        InitializeComponent();

        _telemetry = telemetry;

        // Compact window.
        AppWindow.Resize(new SizeInt32(390, 710));

        // System tray.
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

        // X hides the window, monitoring continues.
        AppWindow.Closing += (_, e) =>
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                AppWindow.Hide();
            }
        };

        PositionBottomRight();

        // Read shared telemetry directly from memory.
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
    }

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
                $"Window positioning failed: {ex.Message}");
        }
    }

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

    private void OnWindowClosed(
        object sender,
        WindowEventArgs args)
    {
        _refreshTimer.Stop();

        _windowManager.IsVisibleInTray = false;
        _windowManager.Dispose();
    }
}
