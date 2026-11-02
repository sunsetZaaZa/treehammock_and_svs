using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class SessionCacheWarmupSettings
{
    public bool Enabled { get; set; }

    [Range(1, 1000)]
    public int BatchSize { get; set; } = 100;

    [Range(1, 3600)]
    public int IntervalSeconds { get; set; } = 10;

    // Zero keeps replenishing throughout the host lifetime.
    [Range(0, 86400)]
    public int DurationSeconds { get; set; } = 300;

    [Range(1, 86400)]
    public int CacheTtlSeconds { get; set; } = 300;

    [Range(100, 30000)]
    public int BatchTimeoutMilliseconds { get; set; } = 5000;
}
