using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class SensitiveActionSettings
{
    [Range(16, 128)]
    public int TokenBytes { get; set; } = 32;

    [Range(1, 60)]
    public int ExpirationMinutes { get; set; } = 10;

    [Range(1, 20)] public int MaxPasswordAttempts { get; set; } = 5;
    [Range(1, 20)] public int MaxFactorAttempts { get; set; } = 5;
    [Range(60, 3600)] public int AttemptWindowSeconds { get; set; } = 900;
    [Range(1, 60)] public int PasswordProofLeaseSeconds { get; set; } = 30;
    [Range(1, 100)] public int MaxRequestsPerAccount { get; set; } = 20;
    [Range(1, 100)] public int MaxRequestsPerSession { get; set; } = 10;
    [Range(1, 1000)] public int MaxRequestsPerIp { get; set; } = 50;

    // Historical configuration is retained but no longer enables unbound issuance.
    public bool ConsumeExistingTokensOnIssue { get; set; } = true;
}
