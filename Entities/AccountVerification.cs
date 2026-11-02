using System.Diagnostics.CodeAnalysis;

using NodaTime;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Entities;

public class AccountVerification
{
    [SetsRequiredMembers]
    public AccountVerification(Guid accountId, string verifyKey, VerificationStatus verifyStatus, Instant? sentWhen)
    {
        (this.accountId, this.verifyKey, this.verifyStatus, this.sentWhen) =
        (accountId, verifyKey, verifyStatus, sentWhen);
    }

    [SetsRequiredMembers]
    public AccountVerification(Guid accountId, string verifyKey, VerificationStatus verifyStatus, Instant? sentWhen, Period? expiration)
    {
        (this.accountId, this.verifyKey, this.verifyStatus, this.sentWhen, this.expiration) =
        (accountId, verifyKey, verifyStatus, sentWhen, expiration);
    }

    public required Guid accountId { get; set; }
    // Stores the SHA-256 lowercase hex hash of the verification token, never the raw emailed token.
    public required string verifyKey { get; set; }
    public required VerificationStatus verifyStatus { get; set; }
    public required Instant? sentWhen { get; set; }
    public Period? expiration { get; set; }
    public Guid proofVersion { get; set; }
    public Guid accountSecurityStamp { get; set; }
}
