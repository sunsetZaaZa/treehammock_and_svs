using NodaTime;
namespace treehammock.Entities;

// Current lifecycle identity; the durable table stores a one-way verifier, never a clear code.
public sealed record Activations(Guid RequestId, Guid GrantId, Guid AccountId, long GrantVersion,
    Guid OriginStamp, Guid FamilyId, string? ProofHash, Instant ExpiresAt, string State, Instant? ConsumedAt);
