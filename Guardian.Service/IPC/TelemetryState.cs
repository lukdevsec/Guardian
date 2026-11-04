
using System;
using System.Threading;

namespace Guardian.Service.IPC;

/// <summary>
/// Snapshot of the current Guardian monitoring session.
/// Sent to Guardian.Desktop through Named Pipes.
/// </summary>
public sealed record TelemetrySnapshot(
    string ServiceStatus,
    string ProtectionMode,
    long Processes,
    long Connections,
    long Alerts,
    string LastEvent,
    DateTimeOffset Timestamp
);

/// <summary>
/// Thread-safe, in-memory telemetry state shared between
/// Guardian.Service.Worker and PipeServerWorker.
/// </summary>
public sealed class TelemetryState
{
    private long _processes;
    private long _connections;
    private long _alerts;

    private int _monitoringActive;

    private string _lastEvent = "Waiting for events...";

    /// <summary>
    /// Updates the process monitoring status.
    /// </summary>
    public void SetMonitoringActive(bool active)
    {
        Interlocked.Exchange(
            ref _monitoringActive,
            active ? 1 : 0);
    }

    /// <summary>
    /// Records a newly detected process.
    /// </summary>
    public void RecordProcess(string name)
    {
        Interlocked.Increment(ref _processes);

        Volatile.Write(
            ref _lastEvent,
            $"Process started: {name}");
    }

    /// <summary>
    /// Records a newly observed TCP connection.
    /// </summary>
    public void RecordConnection(string address)
    {
        Interlocked.Increment(ref _connections);

        Volatile.Write(
            ref _lastEvent,
            $"TCP connection: {address}");
    }

    /// <summary>
    /// Records a security detection alert.
    /// </summary>
    public void RecordAlert(string description)
    {
        Interlocked.Increment(ref _alerts);

        Volatile.Write(
            ref _lastEvent,
            $"ALERT: {description}");
    }

    /// <summary>
    /// Returns a snapshot suitable for JSON serialization.
    /// </summary>
    public TelemetrySnapshot GetSnapshot()
    {
        bool monitoringActive =
            Volatile.Read(ref _monitoringActive) == 1;

        return new TelemetrySnapshot(
            ServiceStatus: monitoringActive
                ? "Running"
                : "Starting",

            ProtectionMode: "DetectionOnly",

            Processes: Interlocked.Read(
                ref _processes),

            Connections: Interlocked.Read(
                ref _connections),

            Alerts: Interlocked.Read(
                ref _alerts),

            LastEvent: Volatile.Read(
                ref _lastEvent),

            Timestamp: DateTimeOffset.UtcNow
        );
    }
}
