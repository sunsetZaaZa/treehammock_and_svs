using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Services;

public interface IPasswordResetRateLimitKeyFactory
{
    string ForAccount(Guid accountId);

    string ForDestinationFingerprint(string destinationFingerprint);

    string ForIpAddress(string? ipAddress);
}

public interface IPasswordResetAbuseCounterKeyFactory
{
    AbuseCounterKey ForRequestAccount(Guid accountId);

    AbuseCounterKey ForRequestIdentifier(string identifier);

    AbuseCounterKey ForRequestIpAddress(string? ipAddress);

    AbuseCounterKey ForTokenVerificationReset(Guid resetId);

    AbuseCounterKey ForTwoFactorProofReset(Guid resetId);

    AbuseCounterKey ForFinalizeReset(Guid resetId);
}

public interface IPasswordResetAbusePolicy
{
    TimeSpan RequestCooldown { get; }

    TimeSpan DailyRequestWindow { get; }

    TimeSpan RateLimitBlockPeriod { get; }

    bool ShouldRequireCaptcha(int requestCountInWindow);
}

public sealed class PasswordResetRateLimitKeyFactory : IPasswordResetRateLimitKeyFactory
{
    private readonly IOptions<PasswordResetSettings> _settings;

    public PasswordResetRateLimitKeyFactory(IOptions<PasswordResetSettings> settings)
    {
        _settings = settings;
    }

    public string ForAccount(Guid accountId)
    {
        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty account id is required for password reset account rate limiting.", nameof(accountId));
        }

        return $"account:{accountId:N}:password_reset";
    }

    public string ForDestinationFingerprint(string destinationFingerprint)
    {
        if (string.IsNullOrWhiteSpace(destinationFingerprint))
        {
            throw new ArgumentException("A destination fingerprint is required for password reset destination rate limiting.", nameof(destinationFingerprint));
        }

        return $"destination:{NormalizeToken(destinationFingerprint)}:password_reset";
    }

    public string ForIpAddress(string? ipAddress)
    {
        string normalizedIp = NormalizeIpAddress(ipAddress);
        string pepper = _settings.Value.CodeHashPepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("PasswordResetSettings:CodeHashPepper is required before password reset IP rate-limit keys can be created.");
        }

        return $"ip-bucket:{PasswordResetPublicBuckets.For(pepper, $"pwdreset:rate-limit:ip:{normalizedIp}")}:password_reset";
    }

    private static string NormalizeToken(string value)
    {
        return value.Trim().ToLowerInvariant();
    }

    internal static string NormalizeIpAddress(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return "unknown";
        }

        string trimmed = ipAddress.Trim();
        return IPAddress.TryParse(trimmed, out IPAddress? parsed)
            ? parsed.ToString()
            : trimmed.ToLowerInvariant();
    }
}

public sealed class PasswordResetAbuseCounterKeyFactory : IPasswordResetAbuseCounterKeyFactory
{
    private readonly IOptions<PasswordResetSettings> _settings;

    public PasswordResetAbuseCounterKeyFactory(IOptions<PasswordResetSettings> settings)
    {
        _settings = settings;
    }

    public AbuseCounterKey ForRequestAccount(Guid accountId)
    {
        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty account id is required for password reset abuse throttling.", nameof(accountId));
        }

        return new AbuseCounterKey(AbuseFeature.PasswordResetRequest, AbuseCounterDimension.Account, accountId.ToString("N"));
    }

    public AbuseCounterKey ForRequestIdentifier(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw new ArgumentException("A non-empty identifier is required for password reset abuse throttling.", nameof(identifier));
        }

        string normalized = identifier.Trim().ToLowerInvariant();
        return new AbuseCounterKey(
            AbuseFeature.PasswordResetRequest,
            AbuseCounterDimension.IdentifierFingerprint,
            HmacSafeSegment($"pwdreset:request:identifier:{normalized}"));
    }

    public AbuseCounterKey ForRequestIpAddress(string? ipAddress)
    {
        string normalizedIp = PasswordResetRateLimitKeyFactory.NormalizeIpAddress(ipAddress);
        return new AbuseCounterKey(
            AbuseFeature.PasswordResetRequest,
            AbuseCounterDimension.IpFingerprint,
            HmacSafeSegment($"pwdreset:request:ip:{normalizedIp}"));
    }

    public AbuseCounterKey ForTokenVerificationReset(Guid resetId)
    {
        if (resetId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty reset id is required for password reset token-verification abuse throttling.", nameof(resetId));
        }

        return new AbuseCounterKey(
            AbuseFeature.PasswordResetTokenVerification,
            AbuseCounterDimension.Reset,
            HmacSafeSegment($"pwdreset:token-verification:reset:{resetId:N}"));
    }

    public AbuseCounterKey ForTwoFactorProofReset(Guid resetId)
    {
        if (resetId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty reset id is required for password reset 2FA proof abuse throttling.", nameof(resetId));
        }

        return new AbuseCounterKey(
            AbuseFeature.PasswordResetTwoFactorProof,
            AbuseCounterDimension.Reset,
            HmacSafeSegment($"pwdreset:twofactor-proof:reset:{resetId:N}"));
    }

    public AbuseCounterKey ForFinalizeReset(Guid resetId)
    {
        if (resetId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty reset id is required for password reset finalize abuse throttling.", nameof(resetId));
        }

        return new AbuseCounterKey(
            AbuseFeature.PasswordResetFinalize,
            AbuseCounterDimension.Reset,
            HmacSafeSegment($"pwdreset:finalize:reset:{resetId:N}"));
    }

    private string HmacSafeSegment(string material)
    {
        string pepper = _settings.Value.CodeHashPepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("PasswordResetSettings:CodeHashPepper is required before password reset abuse counter keys can be created.");
        }

        return "bucket-" + PasswordResetPublicBuckets.For(pepper, material);
    }
}

public sealed class PasswordResetAbusePolicy : IPasswordResetAbusePolicy
{
    private readonly IOptions<PasswordResetSettings> _settings;

    public PasswordResetAbusePolicy(IOptions<PasswordResetSettings> settings)
    {
        _settings = settings;
    }

    public TimeSpan RequestCooldown => TimeSpan.FromSeconds(_settings.Value.RequestCooldownSeconds);

    public TimeSpan DailyRequestWindow => TimeSpan.FromHours(_settings.Value.DailyRequestWindowHours);

    public TimeSpan RateLimitBlockPeriod => TimeSpan.FromMinutes(_settings.Value.RateLimitBlockMinutes);

    public bool ShouldRequireCaptcha(int requestCountInWindow)
    {
        return _settings.Value.CaptchaChallengeEnabled
            && requestCountInWindow >= _settings.Value.CaptchaChallengeAfterRequests;
    }
}
