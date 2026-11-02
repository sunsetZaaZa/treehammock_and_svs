namespace treehammock.Rigging.Sidewalk;

public enum ProviderDeliveryStatus
{
    Sent,
    Disabled,
    ConfigurationMissing,
    InvalidRequest,
    Rejected,
    RateLimited,
    ProviderUnavailable,
    Failed,
    Unknown,
    HealthBlocked
}

public sealed record ProviderDeliveryResult(
    ProviderDeliveryStatus Status,
    string Provider,
    string? ProviderMessageId = null,
    string? FailureCode = null,
    treehammock.Rigging.Delivery.ProviderHealthEvidence Health = treehammock.Rigging.Delivery.ProviderHealthEvidence.Neutral)
{
    public treehammock.Rigging.Delivery.DeliverySendResult Outcome => new treehammock.Rigging.Delivery.DeliverySendResult(
        Status switch
        {
            ProviderDeliveryStatus.Sent when !string.IsNullOrWhiteSpace(ProviderMessageId) => treehammock.Rigging.Delivery.DeliverySendState.Accepted,
            ProviderDeliveryStatus.Disabled or ProviderDeliveryStatus.ConfigurationMissing or ProviderDeliveryStatus.InvalidRequest or ProviderDeliveryStatus.RateLimited or ProviderDeliveryStatus.HealthBlocked => treehammock.Rigging.Delivery.DeliverySendState.NotSubmitted,
            ProviderDeliveryStatus.Rejected => treehammock.Rigging.Delivery.DeliverySendState.Rejected,
            _ => treehammock.Rigging.Delivery.DeliverySendState.Unknown
        }, "DELIVERY_" + Status.ToString().ToUpperInvariant(), Status is ProviderDeliveryStatus.RateLimited or ProviderDeliveryStatus.HealthBlocked,
        Provider, ProviderMessageId, Health).Normalize();
    public bool Succeeded => Outcome.State == treehammock.Rigging.Delivery.DeliverySendState.Accepted;
    public bool CanFallback => Outcome.State is treehammock.Rigging.Delivery.DeliverySendState.NotSubmitted or treehammock.Rigging.Delivery.DeliverySendState.Rejected;
    public static ProviderDeliveryResult HealthBlocked(string provider) => new(ProviderDeliveryStatus.HealthBlocked,provider,FailureCode:"PROVIDER_HEALTH_BLOCKED");
    public static ProviderDeliveryResult Unknown(string provider, string? reason = null) => new(ProviderDeliveryStatus.Unknown, provider, FailureCode: reason ?? "ACCEPTANCE_UNKNOWN");

    public static ProviderDeliveryResult Sent(string provider, string providerMessageId) =>
        new(ProviderDeliveryStatus.Sent, provider, providerMessageId, Health: treehammock.Rigging.Delivery.ProviderHealthEvidence.Healthy);

    public static ProviderDeliveryResult Disabled(string provider) =>
        new(ProviderDeliveryStatus.Disabled, provider, FailureCode: "PROVIDER_DISABLED");

    public static ProviderDeliveryResult ConfigurationMissing(string provider, string settingName) =>
        new(ProviderDeliveryStatus.ConfigurationMissing, provider, FailureCode: $"CONFIGURATION_MISSING:{settingName}");

    public static ProviderDeliveryResult InvalidRequest(string provider, string reason) =>
        new(ProviderDeliveryStatus.InvalidRequest, provider, FailureCode: reason);

    public static ProviderDeliveryResult Rejected(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.Rejected, provider, FailureCode: reason ?? "REJECTED");

    public static ProviderDeliveryResult RateLimited(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.RateLimited, provider, FailureCode: reason ?? "RATE_LIMITED", Health: treehammock.Rigging.Delivery.ProviderHealthEvidence.Outage);

    public static ProviderDeliveryResult ProviderUnavailable(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.ProviderUnavailable, provider, FailureCode: reason ?? "PROVIDER_UNAVAILABLE");

    public static ProviderDeliveryResult Failed(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.Failed, provider, FailureCode: reason ?? "FAILED");
}
