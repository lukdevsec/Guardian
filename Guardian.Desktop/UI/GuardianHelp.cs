
using System;
using System.Threading.Tasks;

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Guardian.Desktop.UI;

public static class GuardianHelp
{
    public static Task ShowEndpointAsync(XamlRoot root)
    {
        return ShowAsync(
            root,
            "Endpoint Monitoring",
            """
            WHAT DOES IT DO?

            Guardian monitors Windows processes and TCP network connections.
            The monitoring engine operates in the background, independently
            of the Vision screen analysis.

            HOW DOES IT WORK?

            1. Reads currently running processes.
            2. Tracks changes in process activity.
            3. Collects information about TCP connections.
            4. Passes monitored events through the detection engine.
            5. Displays counters and the latest event in Guardian.

            HOW ARE ALERTS DETECTED?

            Alerts depend on the detection rules implemented in the
            Guardian.Core detection engine.

            An unfamiliar process or network connection is not
            automatically malware.

            The process and connection counts show monitored activity,
            not the number of threats.

            WINDOWS NOTIFICATIONS

            The current Windows notification integration is connected
            to high-risk Guardian Vision reports.

            Endpoint monitoring notifications are not yet integrated
            into that notification pipeline.

            CURRENT LIMITATIONS

            Guardian is a developing security analysis tool.
            It does not replace a full antivirus or EDR system.

            It does not automatically block suspicious processes
            or network connections.
            """);
    }

    public static Task ShowVisionAsync(XamlRoot root)
    {
        return ShowAsync(
            root,
            "Guardian Vision",
            """
            WHAT DOES IT DO?

            Guardian Vision examines the visible content of a selected
            browser window to identify potentially suspicious websites.

            It combines:

            • Windows screen capture
            • Local OCR text recognition
            • Browser address reading through UI Automation
            • URL-based phishing heuristics

            HOW TO USE — MANUAL MODE

            1. Open Edge or Chrome.
            2. Click "Analyze selected window".
            3. Select the browser window in the Windows picker.
            4. Guardian reads the address and visible content.
            5. Open "View analysis details" to inspect the report.

            HOW TO USE — CONTINUOUS MODE

            1. Click "Start continuous monitoring".
            2. Select the browser window.
            3. Keep that browser window open.
            4. Guardian analyzes new captured frames periodically.
            5. Click "Stop continuous monitoring" to finish.

            You select the window once per capture session,
            not once for every website you visit.

            HOW IS RISK CALCULATED?

            The current engine checks URL characteristics such as:

            • IP address used instead of a domain
            • User information embedded in a URL
            • Punycode hostname labels
            • Login-related content over HTTP
            • URL shortening services
            • Unusually deep subdomain structure
            • Certain account-verification keywords

            Risk levels:

            LOW:       0–19
            MEDIUM:   20–39
            HIGH:     40–69
            CRITICAL: 70–100

            These are heuristic scores, not probabilities.

            The current version does not automatically classify
            a brand mention as phishing.

            WINDOWS SECURITY ALERTS

            Guardian submits a Windows notification when a new
            Vision report is classified HIGH or CRITICAL.

            To prevent repeated notifications, alerts for the
            same domain and risk level have a cooldown period.

            MEDIUM findings appear in the application but do
            not currently trigger Windows notifications.

            IMPORTANT LIMITATIONS

            OCR can make mistakes.

            Guardian uses the browser address reader instead of
            treating URLs extracted by OCR as the active address.

            If the address cannot be read reliably, Guardian
            should report UNKNOWN instead of inventing a verdict.

            A LOW result does not guarantee website safety.

            PRIVACY

            Image recognition runs locally.
            The prototype does not upload screenshots to an
            external AI analysis service.

            Avoid monitoring windows containing sensitive
            information, such as passwords or financial records.
            """);
    }

    private static async Task ShowAsync(
        XamlRoot root,
        string title,
        string description)
    {
        var content = new TextBlock
        {
            Text = description,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(
                Windows.UI.Color.FromArgb(
                    255, 211, 226, 243)),
            FontSize = 13
        };

        var scroll = new ScrollViewer
        {
            Content = content,
            MaxHeight = 470,
            VerticalScrollBarVisibility =
                ScrollBarVisibility.Auto
        };

        var dialog = new ContentDialog
        {
            XamlRoot = root,
            Title = title,
            Content = scroll,
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
            Background = new SolidColorBrush(
                Windows.UI.Color.FromArgb(
                    255, 25, 39, 60))
        };

        await dialog.ShowAsync();
    }
}
