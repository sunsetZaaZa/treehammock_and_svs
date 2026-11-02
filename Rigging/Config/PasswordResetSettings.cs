using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class PasswordResetSettings : IValidatableObject
{
    public const int MinimumCodeLength = 6;
    public const int MaximumCodeLength = 16;

    [Range(MinimumCodeLength, MaximumCodeLength)]
    public int CodeLength { get; set; } = 8;

    [Required]
    [MinLength(16)]
    public string CodeHashPepper { get; set; } = string.Empty;

    [Range(2, 60)]
    public int ExpirationMinutes { get; set; } = 2;

    [Range(1, 10)]
    public int MaxAttempts { get; set; } = 5;

    [Range(0, 3600)]
    public int RequestCooldownSeconds { get; set; } = 60;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerAccount { get; set; } = 5;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerDestination { get; set; } = 5;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerIp { get; set; } = 20;

    [Range(1, 168)]
    public int DailyRequestWindowHours { get; set; } = 24;

    [Range(1, 1440)]
    public int RateLimitBlockMinutes { get; set; } = 30;

    public bool CaptchaChallengeEnabled { get; set; } = false;

    [Range(1, 100)]
    public int CaptchaChallengeAfterRequests { get; set; } = 3;

    public string CaptchaProvider { get; set; } = "Turnstile";
    public string CaptchaSiteKey { get; set; } = string.Empty;
    public string CaptchaSecretKey { get; set; } = string.Empty;
    public string[] CaptchaAllowedHostnames { get; set; } = [];
    [Range(100, 10000)] public int CaptchaTimeoutMilliseconds { get; set; } = 2000;
    [Range(30, 300)] public int CaptchaContinuationSeconds { get; set; } = 180;
    [Range(1, 10000)] public int PublicRequestsPerMinute { get; set; } = 600;
    [Range(1, 100000)] public int PublicProofsPerMinute { get; set; } = 3000;
    [Range(1, 1000)] public int PublicProofsPerIpBucketPerMinute { get; set; } = 60;
    [Range(50, 2000)] public int PublicRequestResponseFloorMilliseconds { get; set; } = 250;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (CaptchaChallengeEnabled && (CaptchaProvider != "Turnstile" ||
            string.IsNullOrWhiteSpace(CaptchaSiteKey) || string.IsNullOrWhiteSpace(CaptchaSecretKey) ||
            CaptchaSiteKey.StartsWith("1x") || CaptchaSiteKey.StartsWith("2x") || CaptchaSiteKey.StartsWith("3x") ||
            CaptchaSecretKey.StartsWith("1x") || CaptchaSecretKey.StartsWith("2x") || CaptchaSecretKey.StartsWith("3x") ||
            CaptchaAllowedHostnames.Length == 0 || CaptchaAllowedHostnames.Any(h =>
                Uri.CheckHostName(h) != UriHostNameType.Dns || h == "localhost")))
            yield return new ValidationResult("Enabled CAPTCHA requires Turnstile production keys and explicit DNS hostnames; test keys are forbidden.");
    }
}
