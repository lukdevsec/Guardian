
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using Guardian.Core.Models;

namespace Guardian.Monitoring.Processes;

public sealed class ProcessMonitor : IDisposable
{
    private ManagementEventWatcher? _watcher;
    private Timer? _pollTimer;

    private readonly object _pollLock = new();

    private HashSet<int> _knownProcesses = new();

    private bool _baselineReady;
    private bool _disposed;

    public string Mode { get; private set; } = "Not started";

    public event EventHandler<ProcessEvent>? ProcessStarted;

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_watcher != null || _pollTimer != null)
        {
            throw new InvalidOperationException(
                "Process monitor is already running.");
        }

        ManagementEventWatcher? watcher = null;

        try
        {
            var scope = new ManagementScope(
                @"\\.\root\CIMV2");

            scope.Connect();

            var query = new WqlEventQuery(
                "SELECT * FROM Win32_ProcessStartTrace");

            watcher = new ManagementEventWatcher(
                scope, query);

            watcher.EventArrived += OnWmiProcessStarted;

            watcher.Start();

            _watcher = watcher;
            Mode = "WMI event monitoring";

            return;
        }
        catch (ManagementException ex)
        {
            if (watcher != null)
            {
                watcher.EventArrived -= OnWmiProcessStarted;
                watcher.Dispose();
            }

            Debug.WriteLine(
                $"Guardian WMI unavailable: {ex.Message}");

            StartPollingFallback();

            Mode = "Polling fallback - WMI unavailable";
        }
        catch
        {
            if (watcher != null)
            {
                watcher.EventArrived -= OnWmiProcessStarted;
                watcher.Dispose();
            }

            throw;
        }
    }

    // ==========================================
    // WMI EVENT MONITORING
    // ==========================================

    private void OnWmiProcessStarted(
        object sender,
        EventArrivedEventArgs e)
    {
        try
        {
            var data = e.NewEvent;

            string name =
                Convert.ToString(data["ProcessName"])
                ?? "Unknown";

            int pid = Convert.ToInt32(
                data["ProcessID"]);

            int parentPid = Convert.ToInt32(
                data["ParentProcessID"]);

            var process = new ProcessEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                Name = name,
                ProcessId = pid,
                ParentProcessId = parentPid,
                ParentName = GetProcessName(parentPid),
                CommandLine = GetCommandLine(pid)
            };

            ProcessStarted?.Invoke(this, process);
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian WMI event error: {ex.Message}");
        }
    }

    // ==========================================
    // POLLING FALLBACK
    // ==========================================

    private void StartPollingFallback()
    {
        // Establish baseline without reporting all
        // currently running processes as new events.
        PollProcesses(null);

        _pollTimer = new Timer(
            PollProcesses,
            null,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(1));
    }


    private void PollProcesses(object? state)
    {
        var newEvents = new List<ProcessEvent>();

        lock (_pollLock)
        {
            if (_disposed)
                return;

            var currentProcesses = new HashSet<int>();

            Process[] processes;

            try
            {
                processes = Process.GetProcesses();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"Guardian process enumeration error: {ex.Message}");

                return;
            }

            foreach (Process process in processes)
            {
                using (process)
                {
                    try
                    {
                        int pid = process.Id;
                        string name = process.ProcessName;

                        if (!name.EndsWith(
                            ".exe",
                            StringComparison.OrdinalIgnoreCase))
                        {
                            name += ".exe";
                        }

                        currentProcesses.Add(pid);

                        if (_baselineReady &&
                            !_knownProcesses.Contains(pid))
                        {
                            newEvents.Add(new ProcessEvent
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                Name = name,
                                ProcessId = pid,
                                ParentProcessId = 0,
                                ParentName = "Unknown",
                                CommandLine = null
                            });
                        }
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        // Windows denied access to a protected process.
                        // Skip it without interrupting monitoring.
                    }
                    catch (InvalidOperationException)
                    {
                        // Process exited during enumeration.
                    }
                }
            }

            _knownProcesses = currentProcesses;
            _baselineReady = true;
        }

        foreach (var process in newEvents)
        {
            try
            {
                ProcessStarted?.Invoke(this, process);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"Guardian process event error: {ex.Message}");
            }
        }
    }


    // ==========================================
    // PROCESS INFORMATION
    // ==========================================

    private static string GetProcessName(int pid)
    {
        try
        {
            using var process =
                Process.GetProcessById(pid);

            return process.ProcessName;
        }
        catch (Exception ex) when (
            ex is ArgumentException or
            InvalidOperationException or
            System.ComponentModel.Win32Exception)
        {
            return "Unknown";
        }
    }

    private static string? GetCommandLine(int pid)
    {
        try
        {
            using var searcher =
                new ManagementObjectSearcher(
                    "root\\CIMV2",
                    "SELECT CommandLine FROM Win32_Process " +
                    $"WHERE ProcessId = {pid}");

            using var results = searcher.Get();

            foreach (ManagementObject item in results)
            {
                using (item)
                {
                    return item["CommandLine"]?.ToString();
                }
            }
        }
        catch (ManagementException)
        {
            // Command line unavailable.
        }
        catch (UnauthorizedAccessException)
        {
            // Access restricted.
        }

        return null;
    }

    // ==========================================
    // SHUTDOWN
    // ==========================================

    public void Stop()
    {
        if (_disposed)
            return;

        _disposed = true;

        _pollTimer?.Dispose();
        _pollTimer = null;

        if (_watcher != null)
        {
            var watcher = _watcher;
            _watcher = null;

            watcher.EventArrived -= OnWmiProcessStarted;

            try
            {
                watcher.Stop();
            }
            catch (ManagementException)
            {
                // Ignore errors during shutdown.
            }
            finally
            {
                watcher.Dispose();
            }
        }

        Mode = "Stopped";
    }

    public void Dispose()
    {
        Stop();
    }
}
