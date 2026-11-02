using System.ComponentModel.DataAnnotations;


namespace treehammock.Rigging.Config;

public class JWTSettings
{
    [Range(1, 86400)]
    public int MinimumRefreshIntervalSeconds { get; set; } = 60;

    [Required]
    public string JsonWebTokenIssuer { get; set; } = string.Empty;

    [Range(0, 3660)]
    public int RefreshTokenAliveDays { get; set; } // Cache

    [Range(0, 23)]
    public int RefreshTokenAliveHours { get; set; } // Cache

    [Range(0, 59)]
    public int RefreshTokenAliveMinutes { get; set; } // Cache

    [Range(0, 3660)]
    public int RefreshTokenAliveDays_2FA { get; set; } // Cache

    [Range(0, 23)]
    public int RefreshTokenAliveHours_2FA { get; set; } // Cache

    [Range(0, 59)]
    public int RefreshTokenAliveMinutes_2FA { get; set; } // Cache

    [Range(0, 3660)]
    public int RefreshTokenAliveDays_DB { get; set; } // Database

    [Range(0, 23)]
    public int RefreshTokenAliveHours_DB { get; set; } // Database

    [Range(0, 59)]
    public int RefreshTokenAliveMinutes_DB { get; set; } // Database

    [Range(0, 3660)]
    public int RefreshTokenAliveDays_Short { get; set; } // Cache

    [Range(0, 23)]
    public int RefreshTokenAliveHours_Short { get; set; } // Cache

    [Range(0, 59)]
    public int RefreshTokenAliveMinutes_Short { get; set; } // Cache

    [Range(32, 512)]
    public int RefreshTokenBytes { get; set; }


}
