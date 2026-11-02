using treehammock.RiggingSupport.Enum;
namespace treehammock.Services;

public static class CapabilityCatalog
{
    // Only implemented capabilities are listed. Separate tiers never inherit by numeric rank.
    public static IReadOnlySet<string> ForTier(FeatureSet tier) => tier switch
    {
        FeatureSet.basic or FeatureSet.premium => new HashSet<string>(StringComparer.Ordinal) { "account.read", "account.manage" },
        _ => new HashSet<string>(StringComparer.Ordinal)
    };
}
public sealed class EntitlementResolver
{
    // Grant-derived rights remain closed pending COR21 native qualification.
    public const bool GrantRightsEnabled = false;
    public bool HasCapability(treehammock.DataLayer.Entitlements.EntitlementProjection projection, string capability, NodaTime.Instant now)
        => projection.IsCurrent(projection.AccountId, now) && projection.Allows(capability);
    public IReadOnlySet<string> Resolve() => CapabilityCatalog.ForTier(FeatureSet.basic);
    public bool GrantsCapability(string capability) => GrantRightsEnabled && Resolve().Contains(capability);
}
