namespace treehammock.Entities;

using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;
using treehammock.Rigging.Security;

public class Session
{
    [SetsRequiredMembers]
    public Session(
        Guid accountId,
        byte[] refreshToken,
        short? refreshes,
        short? limit,
        Instant createdOn,
        Period? sessionLifespan,
        Instant accessExpiration,
        Instant sessionExpiration,
        Instant? cutOff = null,
        FeatureSet features = FeatureSet.basic,
        Guid? securityStamp = null,
        Guid? accountSecurityStamp = null,
        Guid? familyId = null,
        long generation = 1,
        int protocolVersion = 2,
        treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements = null)
    {
        this.accountId = accountId;
        this.refreshToken = refreshToken;
        this.refreshes = refreshes;
        this.limit = limit;
        this.createdOn = createdOn;
        this.sessionLifespan = sessionLifespan;
        this.accessExpiration = accessExpiration;
        this.sessionExpiration = sessionExpiration;
        this.cutOff = cutOff;
        this.features = features;
        this.securityStamp = securityStamp is null || securityStamp == Guid.Empty ? Guid.NewGuid() : securityStamp.Value;
        this.accountSecurityStamp = AccountSecurityStampGuard.Require(accountSecurityStamp);
        this.familyId = familyId ?? this.securityStamp;
        if (this.familyId == Guid.Empty || generation < 1 || generation > treehammock.Rigging.Authorization.SessionProtocol.MaximumGeneration || protocolVersion != 2)
            throw new ArgumentException("Invalid session protocol identity.");
        this.generation = generation;
        this.protocolVersion = protocolVersion;
        this.entitlements = entitlements;
    }

    public required Guid accountId { get; set; }
    public required byte[] refreshToken { get; set; }
    public short? refreshes { get; set; }
    public short? limit { get; set; }
    public required Instant createdOn { get; set; }

    /// <summary>
    /// Hard database-backed session lifetime. This is not the access-token/cache lifetime.
    /// </summary>
    public Period? sessionLifespan { get; set; }

    /// <summary>
    /// Expiration for the current access token/cache entry.
    /// </summary>
    public required Instant accessExpiration { get; set; }

    /// <summary>
    /// Absolute hard session expiration.
    /// </summary>
    public required Instant sessionExpiration { get; set; }

    public Instant? cutOff { get; set; }
    public FeatureSet features { get; set; } = FeatureSet.basic;
    public required Guid securityStamp { get; set; }

    /// <summary>
    /// Account-wide trust marker captured when the session is created. Cache hits must match the current account marker.
    /// </summary>
    public required Guid accountSecurityStamp { get; set; }

    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; set; }

    public Guid familyId { get; set; }
    public long generation { get; set; }
    public int protocolVersion { get; set; }
}
