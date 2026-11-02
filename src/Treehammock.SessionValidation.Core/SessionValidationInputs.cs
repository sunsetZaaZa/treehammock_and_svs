using System.Collections.Immutable;
using NodaTime;

namespace Treehammock.SessionValidation.Core;

// These are in-process policy inputs, not an admission contract or proof of store coherence.
// The storage coordinator must establish credential binding/current authority before using them.
public readonly record struct SessionIdentity(Guid AccountId, Guid FamilyId, long Generation,
    int ProtocolVersion, Guid SessionStamp, Guid AccountStamp)
{
    public const int CurrentProtocol = 2;
    public const long MaximumGeneration = 9007199254740991;
    public bool IsWellFormed => AccountId != Guid.Empty && FamilyId != Guid.Empty &&
        SessionStamp != Guid.Empty && AccountStamp != Guid.Empty && ProtocolVersion == CurrentProtocol &&
        Generation is >= 1 and <= MaximumGeneration;

    public override string ToString() => nameof(SessionIdentity);
}

public readonly record struct SessionLifetime(Instant AccessExpiration, Instant HardExpiration, Instant? Cutoff)
{
    public Instant EffectiveHardExpiration => Cutoff is { } cutoff && cutoff < HardExpiration ? cutoff : HardExpiration;
}

public enum AccountEligibility { Unknown, Eligible, Locked, Unverified, Disabled, Deleted }

public sealed class EntitlementPolicyInputs
{
    public EntitlementPolicyInputs(Guid accountId, long version, int featureTier, IEnumerable<string>? capabilities,
        bool rightsEnabled, Instant evaluatedAt, Instant? nextBoundary, Instant? eligibilityUntil, bool grantsPresent)
    {
        AccountId = accountId; Version = version; FeatureTier = featureTier;
        Capabilities = capabilities is null ? default : ImmutableArray.CreateRange(capabilities);
        RightsEnabled = rightsEnabled; EvaluatedAt = evaluatedAt; NextBoundary = nextBoundary;
        EligibilityUntil = eligibilityUntil; GrantsPresent = grantsPresent;
    }
    public Guid AccountId { get; }
    public long Version { get; }
    public int FeatureTier { get; }
    public ImmutableArray<string> Capabilities { get; }
    public bool RightsEnabled { get; }
    public Instant EvaluatedAt { get; }
    public Instant? NextBoundary { get; }
    public Instant? EligibilityUntil { get; }
    public bool GrantsPresent { get; }
    public override string ToString() => nameof(EntitlementPolicyInputs);
}

public sealed record SessionValidationInputs(SessionIdentity Identity, SessionIdentity? CurrentAuthorityIdentity,
    SessionLifetime Lifetime, EntitlementPolicyInputs? Entitlements, AccountEligibility AccountState,
    string RequiredCapability, Instant Now, Instant Deadline)
{
    public override string ToString() => nameof(SessionValidationInputs);
}
