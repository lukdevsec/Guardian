using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

using Guardian.Monitoring.Network;

namespace Guardian.Desktop.Endpoint;

public sealed record ProcessInventoryItem(
    int ProcessId,
    string Name,
    long WorkingSetBytes,
    string Path);

public sealed record ProcessInvestigation(
    int ProcessId,
    string Name,
    string Path,
    long WorkingSetBytes,
    DateTimeOffset? StartTime,
    string Company,
    string Product,
    string Description,
    string FileVersion,
    string SignatureStatus,
    int? ParentProcessId,
    string ParentProcessName,
    IReadOnlyList<string> TcpConnections);

/// <summary>
/// Read-only process inventory for the Endpoint UI. Protected or short-lived
/// processes are represented with partial metadata instead of being treated as malicious.
/// </summary>
public static class ProcessInventoryService
{
    private const int WinTrustSuccess = 0;
    private const int WinTrustNoSignature = unchecked((int)0x800B0100);
    private const uint WtdUiNone = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionIgnore = 0;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WtdRevocationCheckNone = 0x00000010;

    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        [In] ref Guid actionId,
        IntPtr trustData);

    public static IReadOnlyList<ProcessInventoryItem> GetSnapshot(int limit = 250)
    {
        var results = new List<ProcessInventoryItem>();

        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    string name = SafeRead(() => process.ProcessName, "Unknown process");
                    int pid = SafeRead(() => process.Id, -1);
                    if (pid <= 0)
                        continue;

                    long memory = SafeRead(() => process.WorkingSet64, 0L);
                    string path = SafeRead(
                        () => process.MainModule?.FileName ?? string.Empty,
                        string.Empty);

                    results.Add(new ProcessInventoryItem(pid, name, memory, path));
                }
                catch (Exception ex) when (IsExpectedProcessException(ex))
                {
                    // The process may have exited or may be protected by Windows.
                }
            }
        }

        return results
            .OrderByDescending(item => item.WorkingSetBytes)
            .Take(Math.Clamp(limit, 1, 1000))
            .ToArray();
    }

    public static ProcessInvestigation GetDetails(int processId)
    {
        using Process process = Process.GetProcessById(processId);

        string name = SafeRead(() => process.ProcessName, "Unknown process");
        long memory = SafeRead(() => process.WorkingSet64, 0L);
        string path = SafeRead(
            () => process.MainModule?.FileName ?? string.Empty,
            string.Empty);
        DateTimeOffset? startTime = null;

        try
        {
            startTime = new DateTimeOffset(process.StartTime);
        }
        catch (Exception ex) when (IsExpectedProcessException(ex))
        {
        }

        string company = string.Empty;
        string product = string.Empty;
        string description = string.Empty;
        string fileVersion = string.Empty;
        string signatureStatus = string.IsNullOrWhiteSpace(path)
            ? "Not checked - executable path unavailable"
            : VerifyAuthenticode(path);

        if (!string.IsNullOrWhiteSpace(path))
        {
            try
            {
                FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
                company = version.CompanyName ?? string.Empty;
                product = version.ProductName ?? string.Empty;
                description = version.FileDescription ?? string.Empty;
                fileVersion = version.FileVersion ?? string.Empty;
            }
            catch (Exception ex) when (
                ex is IOException or UnauthorizedAccessException or ArgumentException or
                System.ComponentModel.Win32Exception)
            {
                description = "File metadata unavailable.";
            }
        }

        (int? parentPid, string parentName) = FindParentFromSessionLog(processId, startTime);

        IReadOnlyList<string> tcpConnections;
        try
        {
            tcpConnections = NetworkMonitor.GetConnections()
                .Where(connection => connection.ProcessId == processId)
                .Select(connection =>
                    $"{connection.LocalAddress}:{connection.LocalPort} -> " +
                    $"{connection.RemoteAddress}:{connection.RemotePort}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(100)
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception)
        {
            tcpConnections = new[] { $"TCP snapshot unavailable: {ex.Message}" };
        }

        return new ProcessInvestigation(
            processId,
            name,
            path,
            memory,
            startTime,
            company,
            product,
            description,
            fileVersion,
            signatureStatus,
            parentPid,
            parentName,
            tcpConnections);
    }

    private static string VerifyAuthenticode(string filePath)
    {
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        IntPtr dataPointer = IntPtr.Zero;

        try
        {
            pathPointer = Marshal.StringToHGlobalUni(filePath);

            var fileInfo = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer,
                FileHandle = IntPtr.Zero,
                KnownSubject = IntPtr.Zero
            };

            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                PolicyCallbackData = IntPtr.Zero,
                SipClientData = IntPtr.Zero,
                UiChoice = WtdUiNone,
                RevocationChecks = 0,
                UnionChoice = WtdChoiceFile,
                FileInfo = fileInfoPointer,
                StateAction = WtdStateActionIgnore,
                StateData = IntPtr.Zero,
                UrlReference = IntPtr.Zero,
                ProviderFlags = WtdCacheOnlyUrlRetrieval | WtdRevocationCheckNone,
                UiContext = 0,
                SignatureSettings = IntPtr.Zero
            };

            dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(trustData, dataPointer, false);

            Guid action = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, dataPointer);

            if (result == WinTrustSuccess)
                return "Valid Authenticode signature (revocation not checked online)";

            if (result == WinTrustNoSignature)
                return "No embedded Authenticode signature";

            return $"Signature not trusted or verification failed (0x{result:X8})";
        }
        catch (Exception ex) when (
            ex is DllNotFoundException or EntryPointNotFoundException or
            MarshalDirectiveException or ArgumentException or
            OutOfMemoryException)
        {
            return $"Signature verification unavailable: {ex.GetType().Name}";
        }
        finally
        {
            if (dataPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(dataPointer);
            if (fileInfoPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(fileInfoPointer);
            if (pathPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(pathPointer);
        }
    }

    private static (int? ParentProcessId, string ParentName) FindParentFromSessionLog(
        int processId,
        DateTimeOffset? processStartTime)
    {
        if (!processStartTime.HasValue)
            return (null, "Not captured for this process start time");

        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Guardian", "Logs", "events.jsonl");

        if (!File.Exists(path))
            return (null, "Not captured in this session");

        try
        {
            foreach (string line in File.ReadLines(path).TakeLast(5000).Reverse())
            {
                try
                {
                    using JsonDocument document = JsonDocument.Parse(line);
                    JsonElement root = document.RootElement;

                    if (!TryGetInt(root, "ProcessId", out int candidatePid) || candidatePid != processId)
                        continue;

                    if (!string.Equals(TryGetString(root, "Type"), "process_start", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string? timestampText = TryGetString(root, "Timestamp");
                    if (!DateTimeOffset.TryParse(timestampText, out DateTimeOffset eventTime) ||
                        Math.Abs((eventTime - processStartTime.Value).TotalSeconds) > 120)
                        continue;

                    int? parentPid = TryGetInt(root, "ParentProcessId", out int value)
                        ? value
                        : null;
                    string parentName = TryGetString(root, "ParentName") ?? "Unknown parent";
                    return (parentPid, parentName);
                }
                catch (JsonException)
                {
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        return (null, "Not captured in this session");
    }

    private static bool TryGetInt(JsonElement element, string property, out int value)
    {
        foreach (JsonProperty item in element.EnumerateObject())
        {
            if (string.Equals(item.Name, property, StringComparison.OrdinalIgnoreCase) &&
                item.Value.TryGetInt32(out value))
                return true;
        }

        value = 0;
        return false;
    }

    private static string? TryGetString(JsonElement element, string property)
    {
        foreach (JsonProperty item in element.EnumerateObject())
        {
            if (string.Equals(item.Name, property, StringComparison.OrdinalIgnoreCase))
                return item.Value.ValueKind == JsonValueKind.String
                    ? item.Value.GetString()
                    : item.Value.ToString();
        }

        return null;
    }

    private static T SafeRead<T>(Func<T> read, T fallback)
    {
        try { return read(); }
        catch (Exception ex) when (IsExpectedProcessException(ex)) { return fallback; }
    }

    private static bool IsExpectedProcessException(Exception ex) =>
        ex is InvalidOperationException or
        System.ComponentModel.Win32Exception or
        NotSupportedException or
        UnauthorizedAccessException or
        ArgumentException;
}
