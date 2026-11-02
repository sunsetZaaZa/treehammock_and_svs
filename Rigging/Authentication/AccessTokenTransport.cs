using Microsoft.AspNetCore.Http;

namespace treehammock.Rigging.Authorization;

public static class AccessTokenTransport
{
    public const string AccessTokenHeaderName = "AccessToken";
    public const string AuthorizationHeaderName = "Authorization";
    public const string BearerScheme = "Bearer";

    public static string? ReadRequestToken(IHeaderDictionary headers)
    {
        string? bearerToken = ReadBearerToken(headers);
        if (!string.IsNullOrWhiteSpace(bearerToken))
        {
            return bearerToken;
        }

        string? legacyHeaderToken = headers[AccessTokenHeaderName].FirstOrDefault();
        return string.IsNullOrWhiteSpace(legacyHeaderToken) ? null : legacyHeaderToken;
    }

    private static string? ReadBearerToken(IHeaderDictionary headers)
    {
        string? authorization = headers[AuthorizationHeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(authorization))
        {
            return null;
        }

        string prefix = $"{BearerScheme} ";
        if (!authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string token = authorization[prefix.Length..].Trim();
        return string.IsNullOrWhiteSpace(token) ? null : token;
    }
}
