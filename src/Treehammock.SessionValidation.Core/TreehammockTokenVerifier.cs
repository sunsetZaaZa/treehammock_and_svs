using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using NodaTime;

namespace Treehammock.SessionValidation.Core;

public static class TreehammockTokenPurpose
{
    public const string ClaimType = "purpose";
    public const string WebKeyClaimType = "webKey";
    public const string Active = "active_v2";
    public const string PreAuthTwoFactor = "preauth_2fa";
}

public interface ITreehammockTokenVerifier
{
    Task<TokenVerificationResult> ValidateAsync(string token, byte[] signingKey, string issuer,
        Instant now, Instant accessExpiration, string expectedPurpose = TreehammockTokenPurpose.Active,
        Duration? refreshWindow = null);
}

// Stateless CPU-only verifier. Caller owns key memory and must not mutate it during the call.
// No token/key is retained, logged, generated, refreshed or returned.
public sealed class TreehammockTokenVerifier : ITreehammockTokenVerifier
{
    public async Task<TokenVerificationResult> ValidateAsync(string token, byte[] signingKey, string issuer,
        Instant now, Instant accessExpiration, string expectedPurpose = TreehammockTokenPurpose.Active,
        Duration? refreshWindow = null)
    {
        // Preserve the existing utility's parameter construction and handler/claim mapping.
        // Bad server configuration/key arguments retain their existing exception boundary.
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKey),
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateLifetime = false
        };
        try
        {
            var handler = new JwtSecurityTokenHandler();
            TokenValidationResult result = await handler.ValidateTokenAsync(token, parameters);
            if (!result.IsValid)
                return new(TokenStatus.Failed, null, TokenFailureReason.TokenHandlerRejected,
                    result.Exception?.GetType().Name ?? "None");

            string? webKey = Claim(result, TreehammockTokenPurpose.WebKeyClaimType);
            string? purpose = Claim(result, TreehammockTokenPurpose.ClaimType);
            string? tokenId = Claim(result, JwtRegisteredClaimNames.Jti);
            if (string.IsNullOrWhiteSpace(webKey) || string.IsNullOrWhiteSpace(purpose) || string.IsNullOrWhiteSpace(tokenId))
                return new(TokenStatus.Malformed, null, TokenFailureReason.MissingRequiredClaims);
            if (!string.Equals(purpose, expectedPurpose, StringComparison.Ordinal))
                return new(TokenStatus.Failed, null, TokenFailureReason.PurposeMismatch);

            Duration window = refreshWindow ?? Duration.Zero;
            Instant refreshStartsAt = accessExpiration.Minus(window);
            if (now < refreshStartsAt) return new(TokenStatus.Passed, webKey);
            if (now < accessExpiration)
                return new(window > Duration.Zero ? TokenStatus.AtExpiration : TokenStatus.Passed, webKey);
            return new(TokenStatus.Expired, webKey);
        }
        catch (SecurityTokenException e)
        {
            return new(TokenStatus.Failed, null, TokenFailureReason.SecurityTokenException, e.GetType().Name);
        }
        catch (Exception e)
        {
            return new(TokenStatus.UnexpectedException, null, TokenFailureReason.UnexpectedException, e.GetType().Name);
        }
    }

    private static string? Claim(TokenValidationResult result, string name)
    {
        if (!result.Claims.TryGetValue(name, out object? value) || value is null) return null;
        string? text = value.ToString();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}
