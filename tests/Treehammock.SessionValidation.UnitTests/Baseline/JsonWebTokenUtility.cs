using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using NodaTime;


namespace Svs02.FrozenBaseline;

public interface IJsonWebTokenUtility
{
    public string GenerateAccessToken(byte[] key, string webKey, string purpose = JsonWebTokenPurpose.Active);
    public Task<(IntraMessage, string?)> ValidateAccessToken(
        string token,
        byte[] refreshToken,
        Instant currentMoment,
        Instant expiration,
        string expectedPurpose = JsonWebTokenPurpose.Active,
        Duration? refreshWindow = null);
}

public static class JsonWebTokenValidationLogReasons
{
    public const string TokenHandlerRejected = "JWT_TOKEN_HANDLER_REJECTED";
    public const string MissingRequiredClaims = "JWT_MISSING_REQUIRED_CLAIMS";
    public const string PurposeMismatch = "JWT_PURPOSE_MISMATCH";
    public const string SecurityTokenException = "JWT_SECURITY_TOKEN_EXCEPTION";
    public const string UnexpectedException = "JWT_UNEXPECTED_VALIDATION_EXCEPTION";
}

public class JsonWebTokenUtility : IJsonWebTokenUtility
{
    private readonly JWTSettings _jwtSettings;
    private readonly ILogger _logger;

    public JsonWebTokenUtility(ILogger<JsonWebTokenUtility> logger, IOptions<JWTSettings> jwtSettings)
    {
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
    }

    public string GenerateAccessToken(byte[] refreshToken, string webKey, string purpose = JsonWebTokenPurpose.Active)
    {
        // Access tokens are signed JWS compact tokens, not encrypted JWT/JWE payloads.
        // Keep claims limited to non-secret routing and validation metadata because clients can read them.
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _jwtSettings.JsonWebTokenIssuer,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JsonWebTokenPurpose.WebKeyClaimType, webKey),
                new Claim(JsonWebTokenPurpose.ClaimType, purpose),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            }),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(refreshToken), SecurityAlgorithms.HmacSha256)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public async Task<(IntraMessage, string?)> ValidateAccessToken(
        string token,
        byte[] refreshToken,
        Instant currentMoment,
        Instant expiration,
        string expectedPurpose = JsonWebTokenPurpose.Active,
        Duration? refreshWindow = null)
    {
        TokenValidationParameters accessTokenParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(refreshToken),
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.JsonWebTokenIssuer,
            ValidateAudience = false,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateLifetime = false
        };

        TokenValidationResult jsonWebToken;
        try
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            jsonWebToken = await tokenHandler.ValidateTokenAsync(token, accessTokenParameters);

            if (!jsonWebToken.IsValid)
            {
                _logger.LogInformation(
                    "Access token validation failed with reason {ReasonCode} and exception type {ExceptionType}.",
                    JsonWebTokenValidationLogReasons.TokenHandlerRejected,
                    SafeExceptionType(jsonWebToken.Exception));
                return (IntraMessage.TOKEN_FAILED_VALIDATION, null);
            }

            string? webKey = GetClaimValue(jsonWebToken, JsonWebTokenPurpose.WebKeyClaimType);
            string? purpose = GetClaimValue(jsonWebToken, JsonWebTokenPurpose.ClaimType);
            string? tokenId = GetClaimValue(jsonWebToken, JwtRegisteredClaimNames.Jti);

            if (string.IsNullOrWhiteSpace(webKey) || string.IsNullOrWhiteSpace(purpose) || string.IsNullOrWhiteSpace(tokenId))
            {
                _logger.LogInformation(
                    "Access token validation failed with reason {ReasonCode}.",
                    JsonWebTokenValidationLogReasons.MissingRequiredClaims);
                return (IntraMessage.TOKEN_VALIDATION_MALFORMED, null);
            }

            if (!string.Equals(purpose, expectedPurpose, StringComparison.Ordinal))
            {
                _logger.LogInformation(
                    "Access token validation failed with reason {ReasonCode}.",
                    JsonWebTokenValidationLogReasons.PurposeMismatch);
                return (IntraMessage.TOKEN_FAILED_VALIDATION, null);
            }

            Duration window = refreshWindow ?? Duration.Zero;
            Instant refreshStartsAt = expiration.Minus(window);

            if (currentMoment < refreshStartsAt)
            {
                return (IntraMessage.TOKEN_PASSED_VALIDATION, webKey);
            }

            if (currentMoment < expiration)
            {
                return (window > Duration.Zero)
                    ? (IntraMessage.TOKEN_AT_EXPIRATION, webKey)
                    : (IntraMessage.TOKEN_PASSED_VALIDATION, webKey);
            }

            return (IntraMessage.TOKEN_EXPIRED_VALIDATION, webKey);
        }
        catch (SecurityTokenException e)
        {
            _logger.LogInformation(
                "Access token validation failed with reason {ReasonCode} and exception type {ExceptionType}.",
                JsonWebTokenValidationLogReasons.SecurityTokenException,
                SafeExceptionType(e));
            return (IntraMessage.TOKEN_FAILED_VALIDATION, null);
        }
        catch (Exception e)
        {
            _logger.LogWarning(
                "Access token validation failed closed with reason {ReasonCode} and exception type {ExceptionType}.",
                JsonWebTokenValidationLogReasons.UnexpectedException,
                SafeExceptionType(e));
            return (IntraMessage.TOKEN_THREW_EXCEPTION_IN_VALIDATION, null);
        }
    }

    private static string SafeExceptionType(Exception? exception)
    {
        return exception?.GetType().Name ?? "None";
    }

    private static string? GetClaimValue(TokenValidationResult validationResult, string claimType)
    {
        if (!validationResult.Claims.TryGetValue(claimType, out object? claimValue) || claimValue == null)
        {
            return null;
        }

        string? value = claimValue.ToString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
