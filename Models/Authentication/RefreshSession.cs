using System.ComponentModel.DataAnnotations;
using NodaTime;
using treehammock.Rigging.Authorization;

namespace treehammock.Models.Authentication;

public sealed class RefreshSessionRequest : IValidatableObject
{
    public int protocolVersion { get; set; }
    public Guid sessionId { get; set; }
    public long generation { get; set; }
    [Required, RegularExpression("^[A-Za-z0-9_-]{43}$")]
    public string refreshToken { get; set; } = string.Empty;
    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (protocolVersion != SessionProtocol.Version)
            yield return new("Session protocol 2 is required.", [nameof(protocolVersion)]);
        if (sessionId == Guid.Empty) yield return new("sessionId is required.", [nameof(sessionId)]);
        if (generation < 1 || generation >= SessionProtocol.MaximumGeneration)
            yield return new("generation is outside the protocol range.", [nameof(generation)]);
    }
}

public sealed record SessionCredential(int protocolVersion, Guid sessionId, long generation,
    string refreshToken, Instant accessExpiration, Instant refreshExpiration,
    treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements = null);

public sealed record RefreshSessionResponse(string? accessToken = null, SessionCredential? session = null);
