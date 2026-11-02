using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class RequestBodySettings
{
    public const int DefaultDecodedBytes = 1024 * 1024;
    [Range(1, 1024 * 1024)] public int EncodedBytes { get; set; } = 256 * 1024;
    [Range(1, 4 * 1024 * 1024)] public int DecodedBytes { get; set; } = DefaultDecodedBytes;
    [Range(1, 64)] public int ConcurrentRequests { get; set; } = 16;
    [Range(100, 30000)] public int ReadMilliseconds { get; set; } = 5000;
}
