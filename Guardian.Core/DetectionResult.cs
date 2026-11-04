namespace Guardian.Core.Models;

public sealed class DetectionResult
{
    public int Score { get; init; }

    public string Level { get; init; } = "LOW";

    public List<string> Reasons { get; init; } = new();
}