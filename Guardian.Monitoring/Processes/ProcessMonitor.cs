
using System;
using System.Diagnostics;
using System.Management;
using Guardian.Core.Models;

namespace Guardian.Monitoring.Processes;

public sealed class ProcessMonitor : IDisposable
{
    private ManagementEventWatcher? _watcher;

    public event EventHandler<ProcessEvent>? ProcessStarted;

    public void Start()
    {
        if (_watcher != null)
            throw new InvalidOperationException(
                "Process monitor is already running.");

        var scope = new ManagementScope(
            @"\\.\root\CIMV2");

        scope.Connect();

        var query = new WqlEventQuery(
            "SELECT * FROM Win32_ProcessStartTrace");

        var watcher = new ManagementEventWatcher(
            scope, query);

        watcher.EventArrived += OnProcessStarted;

        try
        {
            watcher.Start();
            _watcher = watcher;
        }
        catch
        {
            watcher.EventArrived -= OnProcessStarted;
            watcher.Dispose();
            throw;
        }
    }

    private void OnProcessStarted(
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
                $"Guardian ProcessMonitor error: {ex}");
        }
    }

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
            using var searcher = new ManagementObjectSearcher(
                "root\\CIMV2",
                "SELECT CommandLine FROM Win32_Process " +
                $"WHERE ProcessId = {pid}");

            using var results = searcher.Get();

            foreach (ManagementObject item in results)
            {
                using (item)
                    return item["CommandLine"]?.ToString();
            }
        }
        catch (ManagementException)
        {
            // Process may have exited.
        }
        catch (UnauthorizedAccessException)
        {
            // Command line may be restricted.
        }

        return null;
    }

    public void Stop()
    {
        if (_watcher == null)
            return;

        var watcher = _watcher;
        _watcher = null;

        watcher.EventArrived -= OnProcessStarted;

        try
        {
            watcher.Stop();
        }
        finally
        {
            watcher.Dispose();
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
