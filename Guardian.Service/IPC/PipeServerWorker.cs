
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Guardian.Service.IPC;

public sealed class PipeServerWorker : BackgroundService
{
    private const string PipeName = "Guardian.Telemetry.v1";

    private readonly TelemetryState _state;
    private readonly ILogger<PipeServerWorker> _logger;

    public PipeServerWorker(
        TelemetryState state,
        ILogger<PipeServerWorker> logger)
    {
        _state = state;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Guardian IPC server starting.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.Out,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                _logger.LogInformation(
                    "Waiting for Guardian Desktop...");

                await pipe.WaitForConnectionAsync(
                    stoppingToken);

                _logger.LogInformation(
                    "Guardian Desktop connected.");

                using var writer = new StreamWriter(
                    pipe,
                    new UTF8Encoding(false))
                {
                    AutoFlush = true
                };

                while (!stoppingToken.IsCancellationRequested &&
                       pipe.IsConnected)
                {
                    var snapshot = _state.GetSnapshot();

                    string json =
                        JsonSerializer.Serialize(snapshot);

                    await writer.WriteLineAsync(
                        json.AsMemory(),
                        stoppingToken);

                    await Task.Delay(
                        TimeSpan.FromSeconds(1),
                        stoppingToken);
                }
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (IOException)
            {
                _logger.LogInformation(
                    "Desktop disconnected.");
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex, "Guardian IPC error.");

                try
                {
                    await Task.Delay(
                        TimeSpan.FromSeconds(2),
                        stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }
}
