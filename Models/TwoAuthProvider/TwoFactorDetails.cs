using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.TwoAuthProvider;

public class TwoFactorDetailsRequest
{
    [SetsRequiredMembers]
    public TwoFactorDetailsRequest(string username, List<string> identifier) =>
        (this.username, this.identifier) = (username, identifier);

    public required string username { get; set; }
    public required List<string> identifier { get; set; }
}

public class TwoFactorDetailsResponse
{
    [SetsRequiredMembers]
    public TwoFactorDetailsResponse(string provider) =>
        (this.provider) = (provider);

    public required string provider { get; set; }
}
