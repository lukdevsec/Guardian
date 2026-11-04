
using Guardian.Core.Models;

namespace Guardian.Core.Detection;

public static class DetectionEngine
{
    public static DetectionResult Analyze(ProcessEvent process)
    {
        int score = 0;
        var reasons = new List<string>();

        string name = process.Name.ToLowerInvariant();
        string parent = process.ParentName.ToLowerInvariant();
        string command = process.CommandLine?
            .ToLowerInvariant() ?? "";

        bool isPowerShell =
            name is "powershell.exe" or "powershell"
                or "pwsh.exe" or "pwsh";

        bool officeParent =
            parent is "winword" or "winword.exe"
                or "excel" or "excel.exe"
                or "powerpnt" or "powerpnt.exe"
                or "outlook" or "outlook.exe";

        if (officeParent &&
            (isPowerShell ||
             name is "cmd.exe" or "cmd"
                 or "wscript.exe" or "cscript.exe"))
        {
            score += 70;
            reasons.Add(
                "Office application launched a script interpreter");
        }

        if (isPowerShell &&
            (command.Contains("-encodedcommand") ||
             command.Contains("-enc ") ||
             command.Contains("frombase64string")))
        {
            score += 65;
            reasons.Add(
                "PowerShell encoded command indicator");
        }

        if (isPowerShell &&
            (command.Contains("downloadstring") ||
             command.Contains("downloadfile") ||
             command.Contains("invoke-webrequest") ||
             command.Contains("iwr ")))
        {
            score += 35;
            reasons.Add(
                "PowerShell download-related command");
        }

        if (isPowerShell &&
            (command.Contains("-noprofile") ||
             command.Contains("-nop ")))
        {
            score += 10;
            reasons.Add(
                "PowerShell launched without user profile");
        }

        if (officeParent &&
            name is "mshta.exe" or "mshta")
        {
            score += 70;
            reasons.Add(
                "Office application launched mshta");
        }

        score = Math.Min(score, 100);

        string level = score switch
        {
            >= 70 => "HIGH",
            >= 30 => "MEDIUM",
            _ => "LOW"
        };

        return new DetectionResult
        {
            Score = score,
            Level = level,
            Reasons = reasons
        };
    }
}
