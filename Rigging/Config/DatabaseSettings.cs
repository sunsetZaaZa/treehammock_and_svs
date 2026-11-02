using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class DatabaseSettings
{
    [Required]
    public string servers { get; set; } = string.Empty;

    [Required]
    public string database { get; set; } = string.Empty;

    [Required]
    public string userId { get; set; } = string.Empty;

    [Required]
    public string password { get; set; } = string.Empty;

    // Local is explicit plaintext; Production requires certificate and hostname verification.
    public string profile { get; set; } = "Local";
    public string? rootCertificate { get; set; }
    [Range(1, 65535)] public int port { get; set; } = 5432;
    [Range(1, 1000)] public int maximumPoolSize { get; set; } = 100;
    [Range(0, 1000)] public int minimumPoolSize { get; set; } = 0;
    [Range(1, 60)] public int connectionTimeoutSeconds { get; set; } = 5;
    [Range(1, 300)] public int commandTimeoutSeconds { get; set; } = 30;
    [Range(1, 10000)] public int cancellationTimeoutMilliseconds { get; set; } = 2000;

    [Required]
    public string lc_collation { get; set; } = string.Empty;
}
