using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.DataLayer.Account;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public sealed class AccountSessionsResponse
{
    [SetsRequiredMembers]
    public AccountSessionsResponse(HttpMessage result, IReadOnlyList<AccountSessionSummary>? sessions = null)
    {
        this.result = result;
        this.sessions = sessions ?? Array.Empty<AccountSessionSummary>();
    }

    public required HttpMessage result { get; set; }
    public required IReadOnlyList<AccountSessionSummary> sessions { get; set; }
}

public sealed class AccountSessionRevokeRequest
{
    [SetsRequiredMembers]
    public AccountSessionRevokeRequest(Guid sessionId)
    {
        this.sessionId = sessionId;
    }

    [Required]
    public required Guid sessionId { get; init; }
}

public sealed class AccountSessionRevokeResponse
{
    [SetsRequiredMembers]
    public AccountSessionRevokeResponse(HttpMessage result)
    {
        this.result = result;
    }

    public required HttpMessage result { get; set; }
}
