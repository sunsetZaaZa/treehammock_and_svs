namespace treehammock.Entities;

using treehammock.RiggingSupport.Enum;
using NodaTime;

using System.Diagnostics.CodeAnalysis;

public class AuthenticationProviderToken
{
    [SetsRequiredMembers]
    public AuthenticationProviderToken(long index, Guid accountId, string token, LocalDateTime opened, LocalDateTime expiration, TwoFactorAuthProvider provider, bool closedOff, short priority)
    {
        (this.index, this.accountId, this.token, this.opened, this.expiration, this.provider, this.closedOff, this.priority) =
        (index, accountId, token, opened, expiration, provider, closedOff, priority);
    }

    [SetsRequiredMembers]
    public AuthenticationProviderToken(long index, Guid accountId, string token, LocalDateTime opened, LocalDateTime expiration, int networkedProviderTokenId, TwoFactorAuthProvider provider, bool closedOff, short priority)
    {
        (this.index, this.accountId, this.token, this.opened, this.expiration, this.networkedProviderTokenId, this.provider, this.closedOff, this.priority) =
        (index, accountId, token, opened, expiration, networkedProviderTokenId, provider, closedOff, priority);
    }

    public required long index { get; set; }
    public required Guid accountId { get; set; }
    public required string token { get; set; }
    public required LocalDateTime opened { get; set; }
    public required LocalDateTime expiration { get; set; }
    public int networkedProviderTokenId { get; set; }
    public required TwoFactorAuthProvider provider { get; set; }
    public required bool closedOff { get; set; }
    public required short priority { get; set; }
}
