
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FlaUI.Core.Definitions;
using FlaUI.UIA3;

namespace Guardian.Desktop.Vision;

public sealed record BrowserAddressResult(
    bool Success,
    string? Url,
    string Browser,
    string Message,
    string? WindowTitle
);

public sealed class BrowserAddressReader
{
    private static readonly string[] SupportedBrowsers =
    {
        "msedge",
        "chrome"
    };

    public Task<BrowserAddressResult> ReadAsync(
        string? selectedWindowTitle,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(
            () => Read(selectedWindowTitle, cancellationToken),
            cancellationToken);
    }

    private BrowserAddressResult Read(
        string? selectedWindowTitle,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        try
        {
            var windows = GetBrowserWindows();

            if (windows.Count == 0)
            {
                return Failure(
                    "No supported browser window was found.",
                    selectedWindowTitle);
            }

            // Match the browser window selected by Windows Capture.
            var selected = windows.FirstOrDefault(w =>
                string.Equals(
                    w.Title,
                    selectedWindowTitle,
                    StringComparison.OrdinalIgnoreCase));

            if (selected == null &&
                !string.IsNullOrWhiteSpace(selectedWindowTitle))
            {
                selected = windows
                    .Where(w =>
                        w.Title.Contains(
                            selectedWindowTitle,
                            StringComparison.OrdinalIgnoreCase) ||
                        selectedWindowTitle.Contains(
                            w.Title,
                            StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(w =>
                        Math.Min(w.Title.Length, selectedWindowTitle.Length))
                    .FirstOrDefault();
            }

            // Never guess when multiple browser windows exist.
            if (selected == null && windows.Count == 1)
            {
                selected = windows[0];
            }

            if (selected == null)
            {
                return Failure(
                    "Could not uniquely identify the selected browser window.",
                    selectedWindowTitle);
            }

            token.ThrowIfCancellationRequested();

            using var automation = new UIA3Automation();

            automation.ConnectionTimeout =
                TimeSpan.FromSeconds(3);

            automation.TransactionTimeout =
                TimeSpan.FromSeconds(3);

            var root = automation.FromHandle(selected.Handle);

            var editElements = root.FindAllDescendants(
                cf => cf.ByControlType(ControlType.Edit));

            var candidates = new List<(string Url, int Score)>();

            foreach (var element in editElements)
            {
                token.ThrowIfCancellationRequested();

                try
                {
                    string automationId =
                        element.Properties.AutomationId.ValueOrDefault
                        ?? string.Empty;

                    string name =
                        element.Properties.Name.ValueOrDefault
                        ?? string.Empty;

                    string? value = null;

                    var valuePattern =
                        element.Patterns.Value.PatternOrDefault;

                    if (valuePattern != null)
                    {
                        value = valuePattern.Value.Value;
                    }

                    if (string.IsNullOrWhiteSpace(value))
                        continue;

                    if (!TryNormalizeUrl(value, out string normalized))
                        continue;

                    int score = 10;

                    // Browser address bar identifiers.
                    if (automationId.Contains(
                        "address",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        score += 100;
                    }

                    if (automationId.Contains(
                        "omnibox",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        score += 100;
                    }

                    if (name.Contains(
                        "address",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        score += 40;
                    }

                    if (name.Contains(
                        "search",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        score += 20;
                    }

                    if (value.StartsWith(
                        "https://",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        score += 15;
                    }

                    candidates.Add((normalized, score));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(
                        $"Guardian UIA element skipped: {ex.Message}");
                }
            }

            var best = candidates
                .OrderByDescending(c => c.Score)
                .FirstOrDefault();

            if (string.IsNullOrWhiteSpace(best.Url))
            {
                return Failure(
                    "Browser address bar could not be read through UI Automation.",
                    selected.Title,
                    selected.Browser);
            }

            return new BrowserAddressResult(
                true,
                best.Url,
                selected.Browser,
                "Address read from browser UI Automation.",
                selected.Title);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian BrowserAddressReader error: {ex}");

            return Failure(
                $"Browser address reading failed: {ex.Message}",
                selectedWindowTitle);
        }
    }

    // ==========================================
    // BROWSER WINDOW DISCOVERY
    // ==========================================

    private static List<BrowserWindow> GetBrowserWindows()
    {
        var windows = new List<BrowserWindow>();

        EnumWindows((handle, _) =>
        {
            if (!IsWindowVisible(handle))
                return true;

            int titleLength = GetWindowTextLength(handle);

            if (titleLength <= 0)
                return true;

            var titleBuilder = new StringBuilder(
                titleLength + 1);

            GetWindowText(
                handle,
                titleBuilder,
                titleBuilder.Capacity);

            string title = titleBuilder.ToString();

            GetWindowThreadProcessId(
                handle,
                out uint processId);

            try
            {
                using var process =
                    Process.GetProcessById((int)processId);

                string processName =
                    process.ProcessName.ToLowerInvariant();

                if (!SupportedBrowsers.Contains(processName))
                    return true;

                var classBuilder = new StringBuilder(256);

                GetClassName(
                    handle,
                    classBuilder,
                    classBuilder.Capacity);

                string windowClass = classBuilder.ToString();

                if (!windowClass.Contains(
                    "Chrome_WidgetWin",
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                string browser =
                    processName == "msedge"
                        ? "Microsoft Edge"
                        : "Google Chrome";

                windows.Add(new BrowserWindow(
                    handle,
                    title,
                    browser));
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"Guardian browser discovery: {ex.Message}");
            }

            return true;
        }, IntPtr.Zero);

        return windows;
    }

    // ==========================================
    // URL VALIDATION
    // ==========================================

    private static bool TryNormalizeUrl(
        string value,
        out string normalized)
    {
        normalized = string.Empty;

        value = value.Trim();

        if (string.IsNullOrWhiteSpace(value))
            return false;

        // Do not interpret search queries as website addresses.
        if (value.Any(char.IsWhiteSpace))
            return false;

        string candidate = value;

        if (!candidate.StartsWith(
            "http://",
            StringComparison.OrdinalIgnoreCase) &&
            !candidate.StartsWith(
            "https://",
            StringComparison.OrdinalIgnoreCase))
        {
            candidate = "https://" + candidate;
        }

        if (!Uri.TryCreate(
            candidate,
            UriKind.Absolute,
            out Uri? uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttp &&
            uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        if (uri.HostNameType != UriHostNameType.Dns)
            return false;

        if (!uri.Host.Contains('.'))
            return false;

        normalized = uri.AbsoluteUri;

        return true;
    }

    private static BrowserAddressResult Failure(
        string message,
        string? title,
        string browser = "Unknown")
    {
        return new BrowserAddressResult(
            false,
            null,
            browser,
            message,
            title);
    }

    private sealed record BrowserWindow(
        IntPtr Handle,
        string Title,
        string Browser
    );

    // ==========================================
    // WINDOWS API
    // ==========================================

    private delegate bool EnumWindowsCallback(
        IntPtr handle,
        IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(
        EnumWindowsCallback callback,
        IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(
        IntPtr handle);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(
        IntPtr handle,
        StringBuilder text,
        int maxCount);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(
        IntPtr handle);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(
        IntPtr handle,
        StringBuilder className,
        int maxCount);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(
        IntPtr handle,
        out uint processId);
}
