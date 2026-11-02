using NodaTime;
using treehammock.RiggingSupport.Enum;
namespace treehammock.DataLayer.Security;

public sealed record SensitivePasswordAdmission(Guid AccountId, Guid Stamp, string SessionHash, Guid AttemptId,
    SensitiveActionPurpose Purpose, string TargetHash, int Limit, int WindowSeconds, int LeaseSeconds);
public sealed record SensitiveProofAdmission(bool Result, string Code, byte[]? PasswordHash, bool FactorRequired);
public sealed record SensitivePasswordCompletion(Guid AccountId, Guid Stamp, string SessionHash, Guid AttemptId,
    bool Verified, string HandleHash, string TokenHash, int ExpirationMinutes);
public sealed record SensitiveProofCompletion(bool Result, string Code, Instant? Expiration, bool FactorRequired);
// Created by server validation; it is never deserialized from an HTTP request.
public sealed record SensitiveActionGrant(string SessionHash, string TokenHash, string TargetHash, string CanonicalTarget);
