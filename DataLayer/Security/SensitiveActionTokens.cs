using NodaTime;

using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer.Security;

public sealed record AccountReauthenticationCredentialResult(
    bool Result,
    string Code,
    byte[]? HashedPassword,
    VerificationStatus? VerificationStatus,
    Instant? CutOff,
    Guid? AccountSecurityStamp);

public sealed record SensitiveActionTokenIssueCommandResult(
    bool Result,
    string Code,
    Guid? TokenId,
    Instant? Expiration);

public sealed record SensitiveActionTokenValidationCommandResult(
    bool Result,
    string Code,
    Instant? Expiration);
