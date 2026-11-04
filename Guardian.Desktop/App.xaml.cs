
using System;
using System.Threading;
using System.Threading.Tasks;
using Guardian.Service;
using Guardian.Service.IPC;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.UI.Xaml;

namespace Guardian.Desktop;

public partial class App : Application
{
    private Window? _window;
    private IHost? _host;

    public App()
    {
        InitializeComponent();
    }

    protected override async void OnLaunched(
        LaunchActivatedEventArgs args)
    {
        try
        {
            // Build the application host.
            var builder = Host.CreateApplicationBuilder();

            // Shared telemetry state.
            builder.Services.AddSingleton<TelemetryState>();

            // Start the monitoring engine inside this process.
            builder.Services.AddHostedService<Worker>();

            _host = builder.Build();

            // Start background monitoring.
            await _host.StartAsync();

            // Get shared telemetry directly from memory.
            var telemetry =
                _host.Services.GetRequiredService<TelemetryState>();

            // Create the desktop interface.
            _window = new MainWindow(telemetry);

            _window.Activate();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"Guardian startup failed: {ex}");

            _host?.Dispose();
            _host = null;

            Exit();
        }
    }

    public async Task ShutdownAsync()
    {
        if (_host != null)
        {
            using var timeout =
                new CancellationTokenSource(
                    TimeSpan.FromSeconds(5));

            try
            {
                await _host.StopAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                System.Diagnostics.Debug.WriteLine(
                    "Guardian shutdown timed out.");
            }
            finally
            {
                _host.Dispose();
                _host = null;
            }
        }

        Exit();
    }
}
