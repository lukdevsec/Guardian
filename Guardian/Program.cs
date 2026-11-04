
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guardian.Core.Detection;
using Guardian.Core.Models;
using Guardian.Detection;
using Guardian.Monitoring;

namespace Guardian;

internal static class Program
{
    private static readonly object ConsoleLock = new();
    private static readonly object FileLock = new();

    private static readonly ProcessTracker Tracker = new();

    private static readonly string LogDirectory =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "Guardian",
            "Logs");

    private static readonly string EventsFile =
        Path.Combine(LogDirectory, "events.jsonl");

    private static readonly string AlertsFile =
        Path.Combine(LogDirectory, "alerts.jsonl");

    private static long eventCount;
    private static long networkCount;
    private static long alertCount;

    private static async Task<int> Main(string[] args)
    {
        Console.Title = "Guardian | Behavioral Detection Engine";

        Directory.CreateDirectory(LogDirectory);

        PrintBanner();

        if (args.Contains("--self-test",
            StringComparer.OrdinalIgnoreCase))
        {
            RunSelfTest();
            return 0;
        }

        using var cancellation = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            using var watcher = new ManagementEventWatcher(
                new ManagementScope(@"\\.\root\CIMV2"),
                new WqlEventQuery(
                    "SELECT * FROM Win32_ProcessStartTrace"));

            watcher.EventArrived += OnProcessStarted;
            watcher.Start();

            Print("INFO", "Process monitoring active.",
                ConsoleColor.Green);

            Print("INFO", "TCP IPv4 monitoring starting.",
                ConsoleColor.Green);

            Print("INFO", $"Logs: {LogDirectory}",
                ConsoleColor.Gray);

            Print("INFO", "Press Ctrl+C to stop.",
                ConsoleColor.Gray);

            try
            {
                await MonitorNetworkAsync(cancellation.Token);
            }
            finally
            {
                watcher.Stop();
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (ManagementException ex)
        {
            Print("ERROR", $"WMI: {ex.Message}",
                ConsoleColor.Red);

            return 1;
        }
        catch (Exception ex)
        {
            Print("ERROR", $"{ex.GetType().Name}: {ex.Message}",
                ConsoleColor.Red);

            return 1;
        }

        Print("INFO",
            $"Stopped | Processes: {Interlocked.Read(ref eventCount)}" +
            $" | Connections: {Interlocked.Read(ref networkCount)}" +
            $" | Alerts: {Interlocked.Read(ref alertCount)}",
            ConsoleColor.Cyan);

        return 0;
    }

    private static void OnProcessStarted(
        object sender,
        EventArrivedEventArgs e)
    {
        try
        {
            var data = e.NewEvent;

            string name =
                Convert.ToString(data["ProcessName"])
                ?? "Unknown";

            int pid = Convert.ToInt32(data["ProcessID"]);

            int parentPid =
                Convert.ToInt32(data["ParentProcessID"]);

            var process = new ProcessEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                Name = name,
                ProcessId = pid,
                ParentProcessId = parentPid,
                ParentName = GetProcessName(parentPid),
                CommandLine = GetCommandLine(pid)
            };

            Interlocked.Increment(ref eventCount);

            Print("PROCESS",
                $"{name} | PID: {pid} | PPID: {parentPid}",
                ConsoleColor.DarkGray);

            SaveJson(EventsFile, new
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

            Tracker.Register(process, result);

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
            Print("ERROR",
                $"Process event: {ex.Message}",
                ConsoleColor.Red);
        }
    }

    private static async Task MonitorNetworkAsync(
        CancellationToken token)
    {
        HashSet<string> previous = new();
        bool initialized = false;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var connections =
                    NetworkMonitor.GetConnections();

                HashSet<string> current = new();

                foreach (var connection in connections)
                {
                    string key =
                        $"{connection.ProcessId}|" +
                        $"{connection.LocalAddress}|" +
                        $"{connection.LocalPort}|" +
                        $"{connection.RemoteAddress}|" +
                        $"{connection.RemotePort}";

                    current.Add(key);

                    // The first scan establishes the baseline.
                    if (!initialized || previous.Contains(key))
                        continue;

                    Interlocked.Increment(ref networkCount);

                    Print("NETWORK",
                        $"PID: {connection.ProcessId} | " +
                        $"{connection.LocalAddress}:" +
                        $"{connection.LocalPort} -> " +
                        $"{connection.RemoteAddress}:" +
                        $"{connection.RemotePort}",
                        ConsoleColor.Cyan);

                    SaveJson(EventsFile, new
                    {
                        Type = "tcp_connection_observed",
                        Timestamp = DateTimeOffset.UtcNow,
                        connection.ProcessId,
                        connection.LocalAddress,
                        connection.LocalPort,
                        connection.RemoteAddress,
                        connection.RemotePort
                    });

                    if (Tracker.TryFind(
                        connection.ProcessId,
                        out var suspicious) &&
                        suspicious != null)
                    {
                        int correlatedScore =
                            Math.Min(100, suspicious.Score + 20);

                        string level = correlatedScore >= 70
                            ? "HIGH"
                            : "MEDIUM";

                        RegisterAlert(
                            "behavioral_correlation",
                            connection.ProcessId,
                            suspicious.Name,
                            correlatedScore,
                            level,
                            "Previously suspicious process " +
                            "observed with an established " +
                            "TCP connection to " +
                            connection.RemoteAddress +
                            ":" + connection.RemotePort);
                    }
                }

                previous = current;
                initialized = true;
            }
            catch (Exception ex) when (
                ex is System.ComponentModel.Win32Exception
                or InvalidOperationException
                or OverflowException)
            {
                Print("ERROR",
                    $"Network scan: {ex.Message}",
                    ConsoleColor.Red);
            }

            await Task.Delay(
                TimeSpan.FromSeconds(2),
                token);
        }
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch (Exception ex) when (
            ex is ArgumentException
            or InvalidOperationException
            or System.ComponentModel.Win32Exception)
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
            // Process may already have exited.
        }
        catch (UnauthorizedAccessException)
        {
            // Access to command line may be restricted.
        }

        return null;
    }

    private static void RegisterAlert(
        string type,
        int pid,
        string name,
        int score,
        string level,
        string reason)
    {
        Interlocked.Increment(ref alertCount);

        Print("ALERT",
            $"{level} | {name} | PID: {pid} | " +
            $"Score: {score} | {reason}",
            level == "HIGH"
                ? ConsoleColor.Red
                : ConsoleColor.Yellow);

        SaveJson(AlertsFile, new
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

    private static void SaveJson(
        string path,
        object data)
    {
        try
        {
            string json = JsonSerializer.Serialize(data);

            lock (FileLock)
            {
                File.AppendAllText(
                    path,
                    json + Environment.NewLine);
            }
        }
        catch (IOException ex)
        {
            Print("ERROR",
                $"Log write: {ex.Message}",
                ConsoleColor.Red);
        }
        catch (UnauthorizedAccessException ex)
        {
            Print("ERROR",
                $"Log access: {ex.Message}",
                ConsoleColor.Red);
        }
    }

    private static void Print(
        string type,
        string message,
        ConsoleColor color)
    {
        lock (ConsoleLock)
        {
            Console.ForegroundColor = color;

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss}] " +
                $"[{type}] {message}");

            Console.ResetColor();
        }
    }

    private static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;

        Console.WriteLine("""
        
        ============================================
             GUARDIAN SECURITY
             Behavioral Detection Engine v0.3
        ============================================
        
        Mode: MONITOR ONLY
        Sources: Windows WMI + TCP IPv4
        
        """);

        Console.ResetColor();
    }

    private static void RunSelfTest()
    {
        Print("TEST", "Running synthetic detections.",
            ConsoleColor.Cyan);

        var cases = new[]
        {
            new ProcessEvent
            {
                Name = "notepad.exe",
                ParentName = "explorer"
            },
            new ProcessEvent
            {
                Name = "powershell.exe",
                ParentName = "WINWORD",
                CommandLine = "powershell.exe -NoProfile"
            },
            new ProcessEvent
            {
                Name = "powershell.exe",
                ParentName = "explorer",
                CommandLine =
                    "powershell.exe -EncodedCommand TEST"
            }
        };

        foreach (var process in cases)
        {
            var result = DetectionEngine.Analyze(process);

            Print("TEST",
                $"{process.Name} | {result.Level} | " +
                $"Score: {result.Score}",
                ConsoleColor.Cyan);
        }

        try
        {
            var connections =
                NetworkMonitor.GetConnections();

            Print("TEST",
                $"TCP IPv4 connections: {connections.Count}",
                ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            Print("ERROR",
                $"TCP snapshot failed: {ex.Message}",
                ConsoleColor.Red);
        }
    }
}
