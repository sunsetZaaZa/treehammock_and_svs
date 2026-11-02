using Microsoft.AspNetCore.Http;
using Shouldly;

using treehammock.Rigging.Authorization;

namespace treehammock.Tests.Unit;

public class AccessTokenTransportTests
{
    [Fact]
    public void ReadRequestToken_prefers_authorization_bearer_over_legacy_access_token_header()
    {
        var headers = new HeaderDictionary
        {
            [AccessTokenTransport.AccessTokenHeaderName] = "legacy-token",
            [AccessTokenTransport.AuthorizationHeaderName] = "Bearer bearer-token"
        };

        AccessTokenTransport.ReadRequestToken(headers).ShouldBe("bearer-token");
    }

    [Fact]
    public void ReadRequestToken_falls_back_to_legacy_access_token_header()
    {
        var headers = new HeaderDictionary
        {
            [AccessTokenTransport.AccessTokenHeaderName] = "legacy-token"
        };

        AccessTokenTransport.ReadRequestToken(headers).ShouldBe("legacy-token");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Basic abc123")]
    [InlineData("Bearer   ")]
    public void ReadRequestToken_returns_null_for_missing_or_unsupported_authorization_header(string? authorizationHeader)
    {
        var headers = new HeaderDictionary();
        if (authorizationHeader is not null)
        {
            headers[AccessTokenTransport.AuthorizationHeaderName] = authorizationHeader;
        }

        AccessTokenTransport.ReadRequestToken(headers).ShouldBeNull();
    }
}
