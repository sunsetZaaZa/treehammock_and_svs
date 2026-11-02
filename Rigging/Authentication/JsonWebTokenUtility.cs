using Microsoft.IdentityModel.Tokens;
using Treehammock.SessionValidation.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using NodaTime;

using treehammock.RiggingSupport.Status;
using treehammock.Rigging.Config;
using Microsoft.Extensions.Options;

namespace treehammock.Rigging.Authorization;

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
    private readonly ITreehammockTokenVerifier _tokens;

    public JsonWebTokenUtility(ILogger<JsonWebTokenUtility> logger, IOptions<JWTSettings> jwtSettings, ITreehammockTokenVerifier? tokens = null)
    {
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
        _tokens = tokens ?? new TreehammockTokenVerifier();
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
        TokenVerificationResult result = await _tokens.ValidateAsync(token, refreshToken,
            _jwtSettings.JsonWebTokenIssuer, currentMoment, expiration, expectedPurpose, refreshWindow);
        string? reason = result.Reason switch
        {
            TokenFailureReason.TokenHandlerRejected => JsonWebTokenValidationLogReasons.TokenHandlerRejected,
            TokenFailureReason.MissingRequiredClaims => JsonWebTokenValidationLogReasons.MissingRequiredClaims,
            TokenFailureReason.PurposeMismatch => JsonWebTokenValidationLogReasons.PurposeMismatch,
            TokenFailureReason.SecurityTokenException => JsonWebTokenValidationLogReasons.SecurityTokenException,
            TokenFailureReason.UnexpectedException => JsonWebTokenValidationLogReasons.UnexpectedException,
            _ => null
        };
        if (result.Reason == TokenFailureReason.UnexpectedException)
            _logger.LogWarning(
                "Access token validation failed closed with reason {ReasonCode} and exception type {ExceptionType}.",
                reason, SafeExceptionType(result));
        else if (result.Reason is TokenFailureReason.MissingRequiredClaims or TokenFailureReason.PurposeMismatch)
            _logger.LogInformation("Access token validation failed with reason {ReasonCode}.", reason);
        else if (reason is not null)
            _logger.LogInformation("Access token validation failed with reason {ReasonCode} and exception type {ExceptionType}.",
                reason, SafeExceptionType(result));

        return (result.Status switch
        {
            TokenStatus.Passed => IntraMessage.TOKEN_PASSED_VALIDATION,
            TokenStatus.AtExpiration => IntraMessage.TOKEN_AT_EXPIRATION,
            TokenStatus.Expired => IntraMessage.TOKEN_EXPIRED_VALIDATION,
            TokenStatus.Malformed => IntraMessage.TOKEN_VALIDATION_MALFORMED,
            TokenStatus.UnexpectedException => IntraMessage.TOKEN_THREW_EXCEPTION_IN_VALIDATION,
            _ => IntraMessage.TOKEN_FAILED_VALIDATION
        }, result.WebKey);
    }

    private static string SafeExceptionType(TokenVerificationResult result) => result.ExceptionType ?? "None";
}
