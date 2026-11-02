using treehammock.RiggingSupport.Status;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.TwoAuthProvider;

public class TwoFactorRemoveRequest
{
    [SetsRequiredMembers]
    public TwoFactorRemoveRequest(string username, string identifier, uint provider) =>
    (this.username, this.identifier, this.provider) = (username, identifier, provider);

    public required string username { get; set; }
    public required string identifier { get; set; }
    public required uint provider { get; set; }
}

public class TwoFactorRemoveResponse
{
    [SetsRequiredMembers]
    public TwoFactorRemoveResponse(Pass result) =>
    (this.result) = (result);

    public required Pass result { get; set; }
}
