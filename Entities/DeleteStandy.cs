using NodaTime;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Entities;

public class DeleteStandy
{
    [SetsRequiredMembers]
    public DeleteStandy(Guid accountId, string passPhraseHash, Instant expiration, bool verified) =>
        (this.accountId, this.passPhraseHash, this.expiration, this.verified) =
        (accountId, passPhraseHash, expiration, verified);


    public required Guid accountId { get; set; }
    public string? passPhraseHash { get; set; }
    public string? deleteTokenHash { get; set; }
    public required Instant expiration { get; set; }
    public required bool verified { get; set; }
    public Guid requestId { get; set; }
    public Guid originStamp { get; set; }
    public string? originEmail { get; set; }
    public Guid originFamily { get; set; }
    public string? originFactorPolicy { get; set; }
    public Instant authorizedUntil { get; set; }
}
