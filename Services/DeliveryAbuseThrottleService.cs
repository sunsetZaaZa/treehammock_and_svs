using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;

namespace treehammock.Services;

public sealed record DeliveryAbuseThrottleRequest(
    AbuseFeature Feature,
    string DeliveryMethod,
    Guid? AccountId = null,
    SafeAbuseIdentifier? Destination = null);

public interface IDeliveryAbuseThrottleService
{
    Task<AbuseDecision> ShouldAllowDeliveryAsync(
        DeliveryAbuseThrottleRequest request,
        CancellationToken cancellationToken = default);

    Task RecordProviderFailureAsync(
        DeliveryAbuseThrottleRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class NullDeliveryAbuseThrottleService : IDeliveryAbuseThrottleService
{
    public static NullDeliveryAbuseThrottleService Instance { get; } = new();

    private NullDeliveryAbuseThrottleService()
    {
    }

    public Task<AbuseDecision> ShouldAllowDeliveryAsync(
        DeliveryAbuseThrottleRequest request,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(AbuseDecision.Allow());
    }

    public Task RecordProviderFailureAsync(
        DeliveryAbuseThrottleRequest request,
        CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}

public sealed class DeliveryAbuseThrottleService : IDeliveryAbuseThrottleService
{
    private readonly IAbuseCounterStore _counterStore;
    private readonly AbuseControlSettings _settings;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DeliveryAbuseThrottleService(
        IAbuseCounterStore counterStore,
        IOptions<AbuseControlSettings> settings,
        IHttpContextAccessor httpContextAccessor)
    {
        _counterStore = counterStore;
        _settings = settings.Value;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<AbuseDecision> ShouldAllowDeliveryAsync(
        DeliveryAbuseThrottleRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_settings.Enabled || !_settings.Delivery.Enabled)
        {
            return AbuseDecision.Allow();
        }

        string method = NormalizeMethod(request.DeliveryMethod);
        foreach ((AbuseCounterKey Key, AbuseCounterLimit Limit) item in BuildDeliveryCounterLimits(request, method))
        {
            CounterDecision decision = await _counterStore.IncrementAsync(item.Key, item.Limit, cancellationToken);
            if (!decision.CanAdmit)
            {
                string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
                    ? decision.ReasonCode!
                    : AbuseReasonCodes.DeliveryThrottleExceeded;
                AbuseOperationalTelemetry.RecordDeliveryThrottled(method, reasonCode);

                return AbuseDecision.Deny(
                    reasonCode,
                    decision.RetryAfter);
            }
        }

        return AbuseDecision.Allow();
    }

    public Task RecordProviderFailureAsync(DeliveryAbuseThrottleRequest request,CancellationToken cancellationToken = default)
    {
        // Untyped caller failures have no provider-health evidence. Never mutate shared channel state.
        ArgumentNullException.ThrowIfNull(request);
        return Task.CompletedTask;
    }

    private IEnumerable<(AbuseCounterKey Key, AbuseCounterLimit Limit)> BuildDeliveryCounterLimits(
        DeliveryAbuseThrottleRequest request,
        string method)
    {
        TimeSpan window = TimeSpan.FromHours(1);
        TimeSpan cooldown = TimeSpan.FromSeconds(_settings.Delivery.CooldownSecondsAfterRepeatedFailures);

        int accountLimit = IsSms(method)
            ? _settings.Delivery.MaxSmsDeliveriesPerAccountPerHour
            : _settings.Delivery.MaxEmailDeliveriesPerAccountPerHour;
        int ipLimit = IsSms(method)
            ? _settings.Delivery.MaxSmsDeliveriesPerIpPerHour
            : _settings.Delivery.MaxEmailDeliveriesPerIpPerHour;

        if (request.AccountId is { } accountId && accountId != Guid.Empty)
        {
            yield return (
                new AbuseCounterKey(
                    AbuseFeature.Delivery,
                    AbuseCounterDimension.Account,
                    $"{method}-{accountId:N}"),
                new AbuseCounterLimit(accountLimit, window, cooldown));
        }

        if (request.Destination is not null)
        {
            yield return (
                new AbuseCounterKey(
                    AbuseFeature.Delivery,
                    AbuseCounterDimension.IdentifierFingerprint,
                    $"{method}-{request.Destination.Fingerprint}"),
                new AbuseCounterLimit(accountLimit, window, cooldown));
        }

        SafeAbuseIdentifier ip = SafeIp();
        yield return (
            new AbuseCounterKey(
                AbuseFeature.Delivery,
                AbuseCounterDimension.IpFingerprint,
                $"{method}-{ip.Fingerprint}"),
            new AbuseCounterLimit(ipLimit, window, cooldown));
    }

    private SafeAbuseIdentifier SafeIp()
    {
        string value = ResolveClientIpAddress();
        return new SafeAbuseIdentifier("ip", value.Length, Fingerprint("delivery-ip", value));
    }

    private string ResolveClientIpAddress()
    {
        HttpContext? context = _httpContextAccessor.HttpContext;
        IPAddress? remoteIp = context?.Connection.RemoteIpAddress;
        if (remoteIp is not null)
        {
            return remoteIp.ToString();
        }

        return "unknown";
    }

    public static SafeAbuseIdentifier? SafeDestination(string method, string? destination)
    {
        string trimmed = destination?.Trim() ?? string.Empty;
        if (trimmed.Length == 0)
        {
            return null;
        }

        return new SafeAbuseIdentifier(method, trimmed.Length, Fingerprint($"delivery-{method}", NormalizeDestination(method, trimmed)));
    }

    private static string NormalizeDestination(string method, string destination)
    {
        return IsSms(method)
            ? destination.Trim()
            : destination.Trim().ToLowerInvariant();
    }

    private static string Fingerprint(string purpose, string value)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{purpose}:{value}"));
        return Convert.ToHexString(digest, 0, 8).ToLowerInvariant();
    }

    private static string NormalizeMethod(string method)
    {
        string normalized = method.Trim().ToLowerInvariant();
        return normalized is "sms" or "phone" or "sms_key"
            ? "sms"
            : "email";
    }

    private static bool IsSms(string method)
    {
        return string.Equals(method, "sms", StringComparison.Ordinal);
    }
}
