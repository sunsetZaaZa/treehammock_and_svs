using treehammock.Rigging.Config;
namespace treehammock.Rigging.Abuse;

// Version 1 has equivalent SQL fixed-window/cooldown owners for these exact dimensions.
// Other features keep their cache brake and independent existing durable proof/account limits.
public static class AbuseCounterPolicyCatalog
{
    public const int Version = 1;
    public static bool SupportsPostgreSqlBudget(AbuseFeature feature) => feature is AbuseFeature.Login or AbuseFeature.Delivery;
    public static bool SupportsPostgreSqlBudget(AbuseCounterKey key) => SupportsPostgreSqlBudget(key.Feature) &&
        key.Dimension is AbuseCounterDimension.Account or AbuseCounterDimension.IdentifierFingerprint or AbuseCounterDimension.IpFingerprint;

    public static bool ValidConfiguration(AbuseControlSettings settings)
    {
        var policies = settings.PostgreSqlFallbackPolicies;
        if (policies is null || policies.Count > 2 || policies.Distinct().Count() != policies.Count || policies.Any(p => !SupportsPostgreSqlBudget(p))) return false;
        return settings.CounterFailureMode switch
        {
            AbuseCounterFailureMode.FailClosed => policies.Count == 0,
            AbuseCounterFailureMode.RequirePostgreSqlBudgetV1 => policies.Count > 0,
            _ => false
        };
    }
}

public interface IPostgreSqlAbuseBudgetStore
{
    Task<CounterDecision> IncrementAsync(AbuseCounterKey key, AbuseCounterLimit limit, CancellationToken token);
    Task<CooldownDecision> GetCooldownAsync(AbuseCounterKey key, CancellationToken token);
    Task ResetAsync(AbuseCounterKey key, CancellationToken token);
    Task<int> PurgeExpiredAsync(int batch, bool dryRun, CancellationToken token);
}
