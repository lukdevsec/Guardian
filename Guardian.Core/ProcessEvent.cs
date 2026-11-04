namespace Guardian.Core.Models;

public sealed class ProcessEvent
{
    public DateTimeOffset Timestamp { get; init; }
        = DateTimeOffset.UtcNow;

    public string Name { get; init; } = "";

    public int ProcessId { get; init; }

    public int ParentProcessId { get; init; }

    public string ParentName { get; init; } = "";

    public string? CommandLine { get; init; }
}