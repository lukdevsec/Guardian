
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Guardian.Desktop.IPC;

public sealed record TelemetrySnapshot(
    string ServiceStatus,
    string ProtectionMode,
    long Processes,
    long Connections,
    long Alerts,
    string LastEvent,
    DateTimeOffset Timestamp
);

public sealed class TelemetryClient
{
    private const string PipeName = "Guardian.Telemetry.v1";

    public async Task RunAsync(
        Action<TelemetrySnapshot?> onUpdate,
        CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(
                    ".",
                    PipeName,
                    PipeDirection.In,
                    PipeOptions.Asynchronous);

                await pipe.ConnectAsync(2000, token);

                using var reader = new StreamReader(
                    pipe,
                    Encoding.UTF8);

                while (!token.IsCancellationRequested &&
                       pipe.IsConnected)
                {
                    string? line =
                        await reader.ReadLineAsync(token);

                    if (line == null)
                        break;

                    try
                    {
                        TelemetrySnapshot? snapshot =
                            JsonSerializer.Deserialize<TelemetrySnapshot>(
                                line);

                        if (snapshot != null)
                            onUpdate(snapshot);
                    }
                    catch (JsonException)
                    {
                        // Ignore invalid telemetry messages.
                    }
                }
            }
            catch (OperationCanceledException)
                when (token.IsCancellationRequested)
            {
                break;
            }
            catch (TimeoutException)
            {
                // Service is not available yet.
            }
            catch (IOException)
            {
                // Connection lost.
            }
            catch (UnauthorizedAccessException)
            {
                // Current user lacks pipe access.
            }
            catch (Exception)
            {
                // Unexpected connection error.
                // Retry after a short delay.
            }

            if (!token.IsCancellationRequested)
            {
                onUpdate(null);

                try
                {
                    await Task.Delay(
                        TimeSpan.FromSeconds(2),
                        token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }
}
