
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using Guardian.Core.Models;

namespace Guardian.Monitoring.Processes;

public sealed class ProcessTracker
{
    private readonly ConcurrentDictionary<int, TrackedProcess>
        _processes = new();

    private static readonly TimeSpan TrackingWindow =
        TimeSpan.FromMinutes(5);

    public void Register(
        ProcessEvent process,
        DetectionResult detection)
    {
        if (detection.Score < 30)
            return;

        _processes[process.ProcessId] = new TrackedProcess(
            process.ProcessId,
            process.Name,
            process.Timestamp,
            detection.Score,
            detection.Level);
    }

    public bool TryFind(
        int pid,
        out TrackedProcess? tracked)
    {
        tracked = null;

        if (!_processes.TryGetValue(pid, out var candidate))
            return false;

        if (DateTimeOffset.UtcNow - candidate.Timestamp
            > TrackingWindow)
        {
            _processes.TryRemove(pid, out _);
            return false;
        }

        // PID values can be reused by Windows.
        // Check that the current process belongs to
        // approximately the same start event.
        try
        {
            using var process = Process.GetProcessById(pid);

            var actualStart =
                new DateTimeOffset(process.StartTime);

            var difference =
                (actualStart - candidate.Timestamp).Duration();

            if (difference > TimeSpan.FromSeconds(10))
            {
                _processes.TryRemove(pid, out _);
                return false;
            }
        }
        catch (Exception ex) when (
            ex is ArgumentException or
            InvalidOperationException or
            System.ComponentModel.Win32Exception)
        {
            return false;
        }

        tracked = candidate;
        return true;
    }
}

public sealed record TrackedProcess(
    int ProcessId,
    string Name,
    DateTimeOffset Timestamp,
    int Score,
    string Level);
