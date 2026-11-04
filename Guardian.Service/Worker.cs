
using Guardian.Core.Detection;
using Guardian.Core.Models;
using Guardian.Detection;
using Guardian.Monitoring.Network;
using Guardian.Monitoring.Processes;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guardian.Service.IPC;

namespace Guardian.Service;

public sealed class Worker : BackgroundService
{
    private readonly TelemetryState _telemetry;
    private readonly ILogger<Worker> _logger;
    private readonly ProcessTracker _tracker = new();
    private readonly object _fileLock = new();

    private ProcessMonitor? _processMonitor;

    private readonly string _logDirectory = Path.Combine(
        Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData),
        "Guardian",
        "Logs");

    private long _processCount;
    private long _connectionCount;
    private long _alertCount;

    public Worker(
    ILogger<Worker> logger,
    TelemetryState telemetry)
    {
        _logger = logger;
        _telemetry = telemetry;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_logDirectory);

        _logger.LogInformation(
            "Guardian Security Engine v0.5.2 starting.");

        _logger.LogInformation(
            "Mode: MONITOR ONLY");

        _logger.LogInformation(
            "Log directory: {Path}", _logDirectory);

        try
        {
            using var monitor = new ProcessMonitor();
            _processMonitor = monitor;

            monitor.ProcessStarted += OnProcessStarted;
            monitor.Start();
            _telemetry.SetMonitoringActive(true);

            _logger.LogInformation(
                "Windows process monitoring ACTIVE.");

            _logger.LogInformation(
                "TCP IPv4 monitoring ACTIVE.");

            try
            {
                await Task.WhenAll(
                    MonitorNetworkAsync(stoppingToken),
                    HeartbeatAsync(stoppingToken));
            }
            finally
            {
                _telemetry.SetMonitoringActive(false);
                monitor.ProcessStarted -= OnProcessStarted;
                monitor.Stop();
                _processMonitor = null;
            }
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogCritical(
                ex, "Guardian monitoring stopped unexpectedly.");

            throw;
        }
        finally
        {
            _logger.LogInformation(
                "Guardian stopped. Processes: {Processes}, " +
                "TCP events: {Connections}, Alerts: {Alerts}",
                Interlocked.Read(ref _processCount),
                Interlocked.Read(ref _connectionCount),
                Interlocked.Read(ref _alertCount));
        }
    }

    private void OnProcessStarted(
        object? sender,
        ProcessEvent process)
    {
        try
        {
            Interlocked.Increment(ref _processCount);
            _telemetry.RecordProcess(process.Name);

            _logger.LogInformation(
                "[PROCESS] {Name} | PID: {Pid} | PPID: {Ppid}",
                process.Name,
                process.ProcessId,
                process.ParentProcessId);

            SaveEvent(new
            {
                Type = "process_start",
                process.Timestamp,
                process.Name,
                process.ProcessId,
                process.ParentProcessId,
                process.ParentName
            });

            DetectionResult result =
                DetectionEngine.Analyze(process);

            _tracker.Register(process, result);

            if (result.Score >= 30)
            {
                RegisterAlert(
                    "process_detection",
                    process.ProcessId,
                    process.Name,
                    result.Score,
                    result.Level,
                    string.Join("; ", result.Reasons));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex, "Error processing process event.");
        }
    }

    private async Task MonitorNetworkAsync(
        CancellationToken token)
    {
        var previousConnections = new HashSet<string>();

        bool initialized = false;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var connections =
                    NetworkMonitor.GetConnections();

                var currentConnections =
                    new HashSet<string>();

                foreach (var connection in connections)
                {
                    string key =
                        $"{connection.ProcessId}|" +
                        $"{connection.LocalAddress}|" +
                        $"{connection.LocalPort}|" +
                        $"{connection.RemoteAddress}|" +
                        $"{connection.RemotePort}";

                    currentConnections.Add(key);

                    if (!initialized ||
                        previousConnections.Contains(key))
                    {
                        continue;
                    }

                    Interlocked.Increment(
                        ref _connectionCount);
                    _telemetry.RecordConnection(
    $"{connection.RemoteAddress}:{connection.RemotePort}");

                    _logger.LogInformation(
                        "[NETWORK] PID: {Pid} | {Remote}:{Port}",
                        connection.ProcessId,
                        connection.RemoteAddress,
                        connection.RemotePort);

                    SaveEvent(new
                    {
                        Type = "tcp_connection_observed",
                        Timestamp = DateTimeOffset.UtcNow,
                        connection.ProcessId,
                        connection.LocalAddress,
                        connection.LocalPort,
                        connection.RemoteAddress,
                        connection.RemotePort
                    });

                    if (_tracker.TryFind(
                        connection.ProcessId,
                        out var suspicious) &&
                        suspicious is not null)
                    {
                        int score = Math.Min(
                            100, suspicious.Score + 20);

                        string level = score >= 70
                            ? "HIGH"
                            : "MEDIUM";

                        RegisterAlert(
                            "behavioral_correlation",
                            connection.ProcessId,
                            suspicious.Name,
                            score,
                            level,
                            "Suspicious process observed with TCP " +
                            "connection to " +
                            connection.RemoteAddress +
                            ":" + connection.RemotePort);
                    }
                }

                previousConnections = currentConnections;
                initialized = true;
            }
            catch (Exception ex)
                when (ex is not OperationCanceledException)
            {
                _logger.LogError(
                    ex, "TCP monitoring error.");
            }

            await Task.Delay(
                TimeSpan.FromSeconds(2), token);
        }
    }

    private async Task HeartbeatAsync(
        CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            _logger.LogInformation(
                "[HEARTBEAT] Processes: {Processes} | " +
                "Connections: {Connections} | Alerts: {Alerts}",
                Interlocked.Read(ref _processCount),
                Interlocked.Read(ref _connectionCount),
                Interlocked.Read(ref _alertCount));

            await Task.Delay(
                TimeSpan.FromSeconds(10), token);
        }
    }

    private void RegisterAlert(
        string type,
        int pid,
        string name,
        int score,
        string level,
        string reason)
    {
        Interlocked.Increment(ref _alertCount);
        _telemetry.RecordAlert(
    $"{level}: {name} - {reason}");

        _logger.LogWarning(
            "[ALERT] {Level} | {Name} | PID: {Pid} | " +
            "Score: {Score} | {Reason}",
            level, name, pid, score, reason);

        SaveJson("alerts.jsonl", new
        {
            Type = type,
            Timestamp = DateTimeOffset.UtcNow,
            ProcessId = pid,
            ProcessName = name,
            Score = score,
            Level = level,
            Reason = reason,
            Action = "monitor_only"
        });
    }

    private void SaveEvent(object data)
    {
        SaveJson("events.jsonl", data);
    }

    private void SaveJson(string filename, object data)
    {
        try
        {
            string path = Path.Combine(
                _logDirectory, filename);

            string json = JsonSerializer.Serialize(data);

            lock (_fileLock)
            {
                File.AppendAllText(
                    path,
                    json + Environment.NewLine);
            }
        }
        catch (Exception ex)
            when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(
                ex, "Failed to write {Filename}", filename);
        }
    }
}
