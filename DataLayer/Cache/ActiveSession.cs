using System.Diagnostics.CodeAnalysis;

using NodaTime;
using Newtonsoft.Json;

using treehammock.Entities;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer.Cache;

// Keyed/Indexed by hashedAccessToken within Redis
[JsonObject(MemberSerialization.OptIn)]
public class ActiveSession
{
    [JsonConstructor]
    [SetsRequiredMembers]
    public ActiveSession(
        Guid accountId,
        byte[] refreshToken,
        short refreshes,
        Instant createdOn,
        Period sessionLifespan,
        Instant accessExpiration,
        Instant sessionExpiration,
        Instant? cutOff,
        FeatureSet features,
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

    [JsonProperty("accountId", Required = Required.Always, Order = 1)]
    public required Guid accountId { get; set; }

    [JsonProperty("refreshToken", Required = Required.Always, Order = 2)]
    public required byte[] refreshToken { get; set; }

    [JsonProperty("refreshes", Required = Required.Always, Order = 3)]
    public required short refreshes { get; set; }

    [JsonProperty("createdOn", Required = Required.Always, Order = 4)]
    public required Instant createdOn { get; set; }

    /// <summary>
    /// Hard database-backed session lifetime. This is not the access-token/cache lifetime.
    /// </summary>
    [JsonProperty("sessionLifespan", Required = Required.Always, Order = 5)]
    public required Period sessionLifespan { get; set; }

    /// <summary>
    /// Expiration for the current access token/cache entry.
    /// </summary>
    [JsonProperty("accessExpiration", Required = Required.Always, Order = 6)]
    public required Instant accessExpiration { get; set; }

    /// <summary>
    /// Absolute end of the hard session lifetime, independent of the current access token.
    /// </summary>
    [JsonProperty("sessionExpiration", Required = Required.Always, Order = 7)]
    public required Instant sessionExpiration { get; set; }

    [JsonProperty("cutOff", Required = Required.AllowNull, Order = 8)]
    public required Instant? cutOff { get; set; }

    [JsonProperty("features", Required = Required.Always, Order = 9)]
    public required FeatureSet features { get; set; }

    /// <summary>
    /// Session trust marker mirrored into Redis. Cache hits must match the DB row.
    /// </summary>
    [JsonProperty("securityStamp", Required = Required.Always, Order = 10)]
    public required Guid securityStamp { get; set; }

    /// <summary>
    /// Account-wide trust marker mirrored into Redis. Cache hits must match the current account row.
    /// </summary>
    [JsonProperty("accountSecurityStamp", Required = Required.Always, Order = 11)]
    public required Guid accountSecurityStamp { get; set; }

    [JsonProperty("familyId", Required = Required.Always, Order = 12)]
    public Guid familyId { get; set; }
    [JsonProperty("generation", Required = Required.Always, Order = 13)]
    public long generation { get; set; }
    [JsonProperty("protocolVersion", Required = Required.Always, Order = 14)]
    public int protocolVersion { get; set; }

    [JsonProperty("entitlements", Required = Required.Always, Order = 15)]
    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; set; }

    [JsonIgnore]
    public Instant EffectiveSessionExpiration => cutOff is not null && cutOff.Value < sessionExpiration
        ? cutOff.Value
        : sessionExpiration;

    public Session toSession()
    {
        return new Session(this.accountId, this.refreshToken, this.refreshes, null, this.createdOn, this.sessionLifespan, this.accessExpiration, this.sessionExpiration, this.cutOff, this.features, this.securityStamp, this.accountSecurityStamp, this.familyId, this.generation, this.protocolVersion, this.entitlements);
    }
}
