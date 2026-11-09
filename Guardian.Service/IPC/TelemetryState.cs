using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Guardian.Service.IPC;

/// <summary>
/// A recent endpoint event exposed to the desktop dashboard.
/// </summary>
public sealed record TelemetryEventSnapshot(
    string Category,
    string Message,
    DateTimeOffset Timestamp);

/// <summary>
/// Snapshot of the current Guardian monitoring session.
/// Sent to Guardian.Desktop through Named Pipes and consumed in-process.
/// </summary>
public sealed record TelemetrySnapshot(
    string ServiceStatus,
    string ProtectionMode,
    long Processes,
    long Connections,
    long Alerts,
    string LastEvent,
    DateTimeOffset Timestamp,
    IReadOnlyList<TelemetryEventSnapshot> RecentEvents
);

/// <summary>
/// Thread-safe, in-memory telemetry state shared between
/// Guardian.Service.Worker and the desktop interface.
/// </summary>
public sealed class TelemetryState
{
    private const int RecentEventLimit = 10;

    private readonly object _eventsLock = new();
    private readonly Queue<TelemetryEventSnapshot> _recentEvents = new();

    private long _processes;
    private long _connections;
    private long _alerts;

    private int _monitoringActive;
    private string _lastEvent = "Waiting for events...";

    public void SetMonitoringActive(bool active)
    {
        Interlocked.Exchange(ref _monitoringActive, active ? 1 : 0);
    }

    public void RecordProcess(string name)
    {
        Interlocked.Increment(ref _processes);
        string message = $"Process started: {name}";
        Volatile.Write(ref _lastEvent, message);
        AddRecentEvent("PROCESS", message);
    }

    public void RecordConnection(string address)
    {
        Interlocked.Increment(ref _connections);
        string message = $"TCP connection: {address}";
        Volatile.Write(ref _lastEvent, message);
        AddRecentEvent("TCP", message);
    }

    public void RecordAlert(string description)
    {
        Interlocked.Increment(ref _alerts);
        string message = $"ALERT: {description}";
        Volatile.Write(ref _lastEvent, message);
        AddRecentEvent("ALERT", message);
    }

    private void AddRecentEvent(string category, string message)
    {
        lock (_eventsLock)
        {
            _recentEvents.Enqueue(new TelemetryEventSnapshot(
                category,
                message,
                DateTimeOffset.UtcNow));

            while (_recentEvents.Count > RecentEventLimit)
                _recentEvents.Dequeue();
        }
    }

    private IReadOnlyList<TelemetryEventSnapshot> GetRecentEvents()
    {
        lock (_eventsLock)
        {
            return _recentEvents
                .Reverse()
                .ToArray();
        }
    }

    public TelemetrySnapshot GetSnapshot()
    {
        bool monitoringActive = Volatile.Read(ref _monitoringActive) == 1;

        return new TelemetrySnapshot(
            ServiceStatus: monitoringActive ? "Running" : "Starting",
            ProtectionMode: "DetectionOnly",
            Processes: Interlocked.Read(ref _processes),
            Connections: Interlocked.Read(ref _connections),
            Alerts: Interlocked.Read(ref _alerts),
            LastEvent: Volatile.Read(ref _lastEvent),
            Timestamp: DateTimeOffset.UtcNow,
            RecentEvents: GetRecentEvents());
    }
}
