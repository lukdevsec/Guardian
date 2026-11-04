
using System;
using System.Threading;
using System.Threading.Tasks;
using Guardian.Desktop.IPC;
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
    private CancellationTokenSource? _connectionCts;

    private readonly DispatcherTimer _watchdog;
    private readonly WindowManager _windowManager;

    private DateTimeOffset _lastMessage =
        DateTimeOffset.MinValue;

    private bool _connected;
    private bool _closed;
    private bool _allowClose;

    public MainWindow()
    {
        InitializeComponent();

        // Compact window dimensions.
        AppWindow.Resize(new SizeInt32(390, 710));

        // Initialize Windows system tray.
        _windowManager = WindowManager.Get(this);
        _windowManager.IsVisibleInTray = true;

        // Left-click tray icon.
        _windowManager.TrayIconSelected += (_, _) =>
        {
            ShowGuardianWindow();
        };

        // Right-click tray icon.
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

            exitItem.Click += (_, _) =>
            {
                ExitApplication();
            };

            menu.Items.Add(openItem);
            menu.Items.Add(new MenuFlyoutSeparator());
            menu.Items.Add(exitItem);

            e.Flyout = menu;
        };

        // Clicking X hides the window instead of exiting.
        AppWindow.Closing += (_, e) =>
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                AppWindow.Hide();
            }
        };

        // Position the window near the bottom-right corner.
        PositionBottomRight();

        // Watchdog for detecting lost IPC connection.
        _watchdog = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2)
        };

        _watchdog.Tick += (_, _) => CheckConnection();
        _watchdog.Start();

        Closed += OnWindowClosed;

        SetOfflineStatus();
        StartConnection();
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
        catch (Exception)
        {
            // Keep the default window position if positioning fails.
        }
    }

    private void ExitApplication()
    {
        _allowClose = true;

        _watchdog.Stop();
        _connectionCts?.Cancel();

        _windowManager.IsVisibleInTray = false;

        Close();
    }

    private void StartConnection()
    {
        _connectionCts?.Cancel();

        var cts = new CancellationTokenSource();
        _connectionCts = cts;

        SetOfflineStatus();

        var client = new TelemetryClient();

        _ = RunConnectionAsync(client, cts);
    }

    private async Task RunConnectionAsync(
        TelemetryClient client,
        CancellationTokenSource cts)
    {
        try
        {
            await client.RunAsync(snapshot =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    if (_closed ||
                        !ReferenceEquals(_connectionCts, cts))
                    {
                        return;
                    }

                    if (snapshot == null)
                    {
                        SetOfflineStatus();
                    }
                    else
                    {
                        ApplySnapshot(snapshot);
                    }
                });
            }, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        finally
        {
            if (ReferenceEquals(_connectionCts, cts))
                _connectionCts = null;

            cts.Dispose();
        }
    }

    private void ApplySnapshot(
        TelemetrySnapshot snapshot)
    {
        _connected = true;
        _lastMessage = DateTimeOffset.UtcNow;

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
                "Guardian service is connected. " +
                "Threat detection is running in " +
                "monitor-only mode.";
        }
        else
        {
            StatusText.Text = "Service starting";

            StatusText.Foreground =
                new SolidColorBrush(Colors.Orange);

            StatusDescription.Text =
                "Guardian service is connected but " +
                "monitoring is not yet confirmed.";
        }
    }

    private void SetOfflineStatus()
    {
        _connected = false;

        StatusText.Text = "Service offline";

        StatusText.Foreground =
            new SolidColorBrush(Colors.OrangeRed);

        StatusDescription.Text =
            "Waiting for Guardian Security Service...";

        UpdatedText.Text =
            "Live connection unavailable";
    }

    private void CheckConnection()
    {
        if (!_connected)
            return;

        if (DateTimeOffset.UtcNow - _lastMessage >
            TimeSpan.FromSeconds(5))
        {
            SetOfflineStatus();
        }
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        StartConnection();
    }

    private void OnWindowClosed(
        object sender,
        WindowEventArgs args)
    {
        _closed = true;

        _watchdog.Stop();
        _connectionCts?.Cancel();

        _windowManager.IsVisibleInTray = false;
        _windowManager.Dispose();
    }
}
