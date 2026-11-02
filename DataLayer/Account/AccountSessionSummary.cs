using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer.Account;

public sealed class AccountSessionSummary
{
    [SetsRequiredMembers]
    public AccountSessionSummary(
        Guid sessionId,
        Instant createdOn,
        Instant accessExpiration,
        Instant sessionExpiration,
        FeatureSet features,
        bool isCurrent, treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements = null)
    {
        this.sessionId = sessionId;
        this.createdOn = createdOn;
        this.accessExpiration = accessExpiration;
        this.sessionExpiration = sessionExpiration;
        this.features = features;
        this.isCurrent = isCurrent;
        this.entitlements = entitlements;
    }

    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; init; }
    public required Guid sessionId { get; init; }
    public required Instant createdOn { get; init; }
    public required Instant accessExpiration { get; init; }
    public required Instant sessionExpiration { get; init; }
    public required FeatureSet features { get; init; }
    public required bool isCurrent { get; init; }
}
