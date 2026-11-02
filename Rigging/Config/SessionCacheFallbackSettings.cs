using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class SessionCacheFallbackSettings
{
    [Range(10, 5000)]
    public int CacheReadTimeoutMilliseconds { get; set; } = 250;

    [Range(10, 5000)]
    public int CacheWriteTimeoutMilliseconds { get; set; } = 250;

    [Range(10, 5000)]
    public int CacheRevokeTimeoutMilliseconds { get; set; } = 250;

    [Range(10, 10000)]
    public int DatabaseFallbackTimeoutMilliseconds { get; set; } = 1000;

    public TimeSpan CacheReadTimeout => TimeSpan.FromMilliseconds(CacheReadTimeoutMilliseconds);

    public TimeSpan CacheWriteTimeout => TimeSpan.FromMilliseconds(CacheWriteTimeoutMilliseconds);

    public TimeSpan CacheRevokeTimeout => TimeSpan.FromMilliseconds(CacheRevokeTimeoutMilliseconds);

    public TimeSpan DatabaseFallbackTimeout => TimeSpan.FromMilliseconds(DatabaseFallbackTimeoutMilliseconds);
}
