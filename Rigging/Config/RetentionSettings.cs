using System.ComponentModel.DataAnnotations;
namespace treehammock.Rigging.Config;

public sealed class RetentionSettings
{
    public bool Enabled { get; set; } = true;
    // Operators inspect bounded dry-run observations before enabling deletions.
    public bool DryRun { get; set; } = true;
    [Range(10, 3600)] public int PollSeconds { get; set; } = 30;
    [Range(1, 100)] public int BatchSize { get; set; } = 100;
    [Range(1, 8)] public int AccountsPerBatch { get; set; } = 8;
    [Range(7, 3650)] public int ProofHistoryDays { get; set; } = 7;
    [Range(90, 3650)] public int AuditHistoryDays { get; set; } = 90;
    [Range(30, 3650)] public int UnverifiedAccountDays { get; set; } = 30;
}
