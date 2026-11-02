using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class UserCacheSettings
{
    [Required]
    public string servers { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int port { get; set; }

    [Range(0, 15)]
    public int database { get; set; }

    [Required]
    public string clientName { get; set; } = string.Empty;

    public bool allowAdmin { get; set; } = false;

    [Range(1, 60000)]
    public uint reconnectRetryPolicy { get; set; } = 5000;

    public bool abortOnConnectFail { get; set; } = false;

    [Range(10, 10000)]
    public int connectTimeoutMilliseconds { get; set; } = 1000;

    [Range(10, 10000)]
    public int asyncTimeoutMilliseconds { get; set; } = 1000;

    [Range(10, 10000)]
    public int syncTimeoutMilliseconds { get; set; } = 1000;

    [Range(0, 10)]
    public int connectRetry { get; set; } = 1;

    public string password { get; set; } = string.Empty;
}
