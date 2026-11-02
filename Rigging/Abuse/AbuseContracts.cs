namespace treehammock.Rigging.Abuse;

public interface IAbusePolicyService
{
    Task<AbuseDecision> EvaluateAsync(
        AbusePolicyRequest request,
        CancellationToken cancellationToken = default);

    Task RecordSuccessAsync(
        AbuseEventRecord record,
        CancellationToken cancellationToken = default);

    Task RecordFailureAsync(
        AbuseEventRecord record,
        CancellationToken cancellationToken = default);
}

public interface IAbuseCounterStore
{
    Task<CounterDecision> IncrementAsync(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        CancellationToken cancellationToken = default);

    Task ResetAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default);

    Task<CooldownDecision> GetCooldownAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default);
}
