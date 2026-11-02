using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.Models.PasswordReset;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Services;

public sealed record PasswordResetCaptchaChallenge(string Provider, string SiteKey, string Action, string Nonce, string Continuation);
public sealed record PasswordResetPublicAdmission(bool Allowed, PasswordResetCaptchaChallenge? Challenge = null);
public interface IPasswordResetPublicGate
{
    Task<PasswordResetPublicAdmission> AdmitRequestAsync(RequestPasswordResetCommand command, CancellationToken cancellationToken);
    Task<bool> AdmitProofAsync(string? ipAddress, CancellationToken cancellationToken);
}

// Fixed HMAC buckets deliberately share budgets on collisions. Arbitrary identifiers never allocate unbounded keys.
public static class PasswordResetPublicBuckets
{
    public const int Count = 4096;
    public static string For(string pepper, string material)
    {
        byte[] hash = HMACSHA256.HashData(Encoding.UTF8.GetBytes(pepper), Encoding.UTF8.GetBytes(material));
        return ((hash[0] * 256 + hash[1]) % Count).ToString(CultureInfo.InvariantCulture);
    }
}

public sealed class PasswordResetPublicGate(IAbuseCounterStore counters, ICaptchaVerifier verifier,
    ICaptchaContinuationStore continuations, IOptions<PasswordResetSettings> options, IClock clock) : IPasswordResetPublicGate
{
    public const string Action = "password_reset_request";
    private readonly PasswordResetSettings settings = options.Value;
    private static bool Allowed(CounterDecision d) => d.CanAdmit && d.CurrentCount > 0 &&
        d.ReasonCode is not (AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout);
    private Task<CounterDecision> Count(string scope, int limit, TimeSpan window, CancellationToken ct) =>
        counters.IncrementAsync(new(AbuseFeature.PasswordResetRequest, AbuseCounterDimension.IpFingerprint, "public-" + scope), new(limit, window), ct);
    private string Ip(string? ip) => PasswordResetPublicBuckets.For(settings.CodeHashPepper,
        "public-ip:" + PasswordResetRateLimitKeyFactory.NormalizeIpAddress(ip));

    public async Task<PasswordResetPublicAdmission> AdmitRequestAsync(RequestPasswordResetCommand command, CancellationToken cancellationToken)
    {
        // Aggregate admission is first, including replay/invalid continuation attempts.
        if (!Allowed(await Count("request-global", settings.PublicRequestsPerMinute, TimeSpan.FromMinutes(1), cancellationToken))) return new(false);
        var count = await Count("request-ip-" + Ip(command.RequestIpAddress), settings.DailyRequestLimitPerIp,
            TimeSpan.FromHours(settings.DailyRequestWindowHours), cancellationToken);
        if (!Allowed(count)) return new(false);
        if (!settings.CaptchaChallengeEnabled) return new(true);
        if (!string.IsNullOrEmpty(command.CaptchaContinuation) || !string.IsNullOrEmpty(command.CaptchaToken))
        {
            if (string.IsNullOrEmpty(command.CaptchaToken) || command.CaptchaToken.Length > 2048 ||
                !TryRead(command, out string nonce)) return new(false);
            // Consume before the external call. Outage/uncertain outcomes cannot retry this authority.
            if (!await continuations.ConsumeAsync(nonce, cancellationToken)) return new(false);
            bool verified = await verifier.VerifyAsync(command.CaptchaToken, Action, nonce, cancellationToken);
            return new(verified && TryRead(command, out _));
        }
        if (count.CurrentCount < settings.CaptchaChallengeAfterRequests) return new(true);
        string fresh = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        long issued = clock.GetCurrentInstant().ToUnixTimeSeconds();
        string body = $"{fresh}.{issued}";
        string ticket = body + "." + Sign(body, command);
        if (!await continuations.CreateAsync(fresh, TimeSpan.FromSeconds(settings.CaptchaContinuationSeconds), cancellationToken)) return new(false);
        return new(false, new("Turnstile", settings.CaptchaSiteKey, Action, fresh, ticket));
    }

    private string Sign(string body, RequestPasswordResetCommand command)
    {
        // Length-delimited JSON prevents separator injection. Identifier never leaves this HMAC boundary.
        string material = System.Text.Json.JsonSerializer.Serialize(new[] { Action, body,
            command.Identifier.Trim().ToLowerInvariant(), PasswordResetDeliveryChannels.Normalize(command.DeliveryChannel),
            PasswordResetRateLimitKeyFactory.NormalizeIpAddress(command.RequestIpAddress) });
        return Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(settings.CodeHashPepper), Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }
    private bool TryRead(RequestPasswordResetCommand command, out string nonce)
    {
        nonce = string.Empty;
        string[] p = (command.CaptchaContinuation ?? "").Split('.');
        if (p.Length != 3 || p[0].Length != 64 || p[2].Length != 64 || !p[0].All(Uri.IsHexDigit) ||
            !long.TryParse(p[1], NumberStyles.None, CultureInfo.InvariantCulture, out long issued)) return false;
        long age = clock.GetCurrentInstant().ToUnixTimeSeconds() - issued;
        if (age < 0 || age >= settings.CaptchaContinuationSeconds) return false;
        byte[] actual = Encoding.ASCII.GetBytes(p[2]), expected = Encoding.ASCII.GetBytes(Sign(p[0] + "." + p[1], command));
        if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return false;
        nonce = p[0]; return true;
    }
    public async Task<bool> AdmitProofAsync(string? ipAddress, CancellationToken cancellationToken)
    {
        if (!Allowed(await Count("proof-global", settings.PublicProofsPerMinute, TimeSpan.FromMinutes(1), cancellationToken))) return false;
        return Allowed(await Count("proof-ip-" + Ip(ipAddress), settings.PublicProofsPerIpBucketPerMinute, TimeSpan.FromMinutes(1), cancellationToken));
    }
}
