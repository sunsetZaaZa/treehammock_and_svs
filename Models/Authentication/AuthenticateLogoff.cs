using treehammock.RiggingSupport.Status;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.Authentication;

public class AuthenticateLogoffRequest
{
    [SetsRequiredMembers]
    public AuthenticateLogoffRequest()
    {

    }
}

public class AuthenticateLogoffResponse
{
    [SetsRequiredMembers]
    public AuthenticateLogoffResponse(HttpMessage result)
    {
        (this.result) = (result);
    }
    public required HttpMessage result { get; set; }
}

public sealed class AuthenticateLogoffAllRequest
{
    [SetsRequiredMembers]
    public AuthenticateLogoffAllRequest()
    {

    }

    public bool includeCurrentSession { get; init; } = true;
}

public sealed class AuthenticateLogoffAllResponse
{
    [SetsRequiredMembers]
    public AuthenticateLogoffAllResponse(HttpMessage result)
    {
        this.result = result;
    }

    public required HttpMessage result { get; set; }
}
