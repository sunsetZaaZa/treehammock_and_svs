using NodaTime;
namespace Svs02.FrozenBaseline;
public enum FeatureSet { basic=1, premium=2 }
public sealed record LegacyEntitlementProjection(System.Guid AccountId, long Version, FeatureSet Features, string[] Capabilities, bool RightsEnabled, Instant EvaluatedAt, Instant? NextBoundary, Instant? EligibilityUntil, object[] Grants)
{
    public bool IsCurrent(Guid account, Instant now) => AccountId == account && account != Guid.Empty &&
        Version is >= 1 and <= 9007199254740991 && (Features is FeatureSet.basic or FeatureSet.premium) &&
        Capabilities is not null && Grants is not null && EvaluatedAt <= now &&
        (NextBoundary is null || NextBoundary > now) &&
        Capabilities.All(c => c is "account.read" or "account.manage") &&
        (RightsEnabled || Features == FeatureSet.basic);
}
