
using System;
using System.Collections.Generic;
using System.Diagnostics;

using Guardian.Desktop.Vision;

using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Guardian.Desktop.Notifications;

public sealed class NotificationService : IDisposable
{
    private readonly Dictionary<string, DateTime> _recentAlerts = new();

    private readonly TimeSpan _cooldown =
        TimeSpan.FromMinutes(10);

    private bool _registered;

    public bool IsAvailable => _registered;

    public event Action? NotificationClicked;

    public NotificationService()
    {
        try
        {
            var manager = AppNotificationManager.Default;

            manager.NotificationInvoked += OnNotificationInvoked;
            manager.Register();

            _registered = true;

            Debug.WriteLine(
                "Guardian notifications registered.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian notifications unavailable: {ex}");
        }
    }

    public bool SendThreatNotification(AnalysisReport report)
    {
        if (!_registered)
            return false;

        if (report.RiskLevel != "HIGH" &&
            report.RiskLevel != "CRITICAL")
        {
            return false;
        }

        // Deduplicate by domain and risk level.
        // A CRITICAL escalation is not suppressed by a HIGH alert.
        string key =
            report.Domain.ToLowerInvariant() +
            "|" + report.RiskLevel;

        DateTime now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(
            key,
            out DateTime previous))
        {
            if (now - previous < _cooldown)
                return false;
        }

        bool sent = Send(
            "Guardian Security Alert",
            $"Potential threat indicators: {report.Domain}",
            $"Risk: {report.RiskLevel} " +
            $"({report.RiskScore?.ToString() ?? "N/A"}/100). " +
            "Click to view the analysis.");

        if (sent)
            _recentAlerts[key] = now;

        return sent;
    }

    public bool SendAiThreatNotification(AnalysisReport report)
    {
        var ai = report.CloudAnalysis;

        if (!_registered || ai == null)
            return false;

        if ((ai.Verdict != "HIGH" && ai.Verdict != "CRITICAL") ||
            ai.Confidence < 75)
        {
            return false;
        }

        string key = "CLOUD_AI|" + report.Domain.ToLowerInvariant() + "|" + ai.Verdict;
        DateTime now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(key, out DateTime previous) &&
            now - previous < _cooldown)
        {
            return false;
        }

        bool sent = Send(
            "Guardian Cloud AI Alert",
            $"Potential high-risk indicators: {report.Domain}",
            $"Claude assessment: {ai.Verdict} ({ai.Confidence}% confidence). Click to review the evidence.");

        if (sent)
            _recentAlerts[key] = now;

        return sent;
    }

    public bool SendTestNotification()
    {
        return Send(
            "Guardian Test Notification",
            "Notification system test",
            "This is a safe test. Click to open Guardian.");
    }

    private bool Send(
        string title,
        string message,
        string description)
    {
        if (!_registered)
            return false;

        try
        {
            var notification =
                new AppNotificationBuilder()
                    .AddArgument("action", "open-report")
                    .AddText(title)
                    .AddText(message)
                    .AddText(description)
                    .BuildNotification();

            AppNotificationManager.Default.Show(notification);

            return true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian notification error: {ex}");

            return false;
        }
    }

    private void OnNotificationInvoked(
        AppNotificationManager sender,
        AppNotificationActivatedEventArgs args)
    {
        try
        {
            NotificationClicked?.Invoke();
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian notification click error: {ex}");
        }
    }

    public void Dispose()
    {
        try
        {
            var manager = AppNotificationManager.Default;

            manager.NotificationInvoked -= OnNotificationInvoked;

            if (_registered)
                manager.Unregister();
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian notification cleanup error: {ex}");
        }

        _registered = false;
    }
}
