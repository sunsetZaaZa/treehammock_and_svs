namespace treehammock.Entities;

using treehammock.RiggingSupport.Enum;
using System.Diagnostics.CodeAnalysis;

public class AuthenticationProvider
{
    [SetsRequiredMembers]
    public AuthenticationProvider(int index, string accessPoint, Protocol_PeerToPeer protocol, string authCreds) =>
        (this.index, this.accessPoint, this.protocol, this.authCreds) = (index, accessPoint, protocol, authCreds);
    public required int index { get; set; }
    public required string accessPoint { get; set; }
    public required Protocol_PeerToPeer protocol { get; set; }
    public required string authCreds { get; set; }
    public string? authPassword { get; set; }
    public string? salt { get; set; }
    public string? authCert { get; set; }
    public string? ports { get; set; }
}
