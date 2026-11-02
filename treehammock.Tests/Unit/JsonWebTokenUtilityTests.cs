using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class JsonWebTokenUtilityTests
{
    [Fact]
    public void GenerateAccessToken_signs_tokens_with_hmac_sha256()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)11, 64).ToArray();

        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        parsedToken.Header.Alg.ShouldBe(SecurityAlgorithms.HmacSha256);
    }

    [Fact]
    public void GenerateAccessToken_emits_signed_compact_jws_not_encrypted_jwe()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)22, 64).ToArray();

        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        token.Split('.').Length.ShouldBe(3);
        parsedToken.Header.Alg.ShouldBe(SecurityAlgorithms.HmacSha256);
        parsedToken.Header.ContainsKey("enc").ShouldBeFalse("Access tokens are signed JWTs, not encrypted JWT/JWE payloads.");
    }

    [Fact]
    public void GenerateAccessToken_uses_only_allowed_non_secret_claims()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)23, 64).ToArray();

        string token = utility.GenerateAccessToken(refreshToken, "web-key", JsonWebTokenPurpose.PreAuthTwoFactor);

        var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        HashSet<string> allowedClaimTypes = new(StringComparer.Ordinal)
        {
            JwtRegisteredClaimNames.Iss,
            JsonWebTokenPurpose.WebKeyClaimType,
            JsonWebTokenPurpose.ClaimType,
            JwtRegisteredClaimNames.Jti,
            JwtRegisteredClaimNames.Iat
        };
        string[] sensitiveClaimFragments =
        [
            "password",
            "refresh",
            "activation",
            "unlock",
            "delete",
            "twoFactorCode",
            "challenge",
            "provider",
            "secret",
            "salt",
            "phone",
            "email"
        ];

        foreach (Claim claim in parsedToken.Claims)
        {
            allowedClaimTypes.ShouldContain(claim.Type, $"Unexpected JWT claim '{claim.Type}' would expand the readable token payload contract.");
            foreach (string sensitiveFragment in sensitiveClaimFragments)
            {
                claim.Type.Contains(sensitiveFragment, StringComparison.OrdinalIgnoreCase)
                    .ShouldBeFalse($"JWT claim '{claim.Type}' looks like sensitive data and must stay out of readable access tokens.");
            }
        }

        parsedToken.Claims.Single(claim => claim.Type == JsonWebTokenPurpose.WebKeyClaimType).Value.ShouldBe("web-key");
        parsedToken.Claims.Single(claim => claim.Type == JsonWebTokenPurpose.ClaimType).Value.ShouldBe(JsonWebTokenPurpose.PreAuthTwoFactor);
    }

    [Fact]
    public void GenerateAccessToken_includes_jti_and_iat_claims()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)16, 64).ToArray();

        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        parsedToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Jti).Value.ShouldNotBeNullOrWhiteSpace();
        parsedToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Iat).Value.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void GenerateAccessToken_same_inputs_produce_different_hashes_because_jti_is_random()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)21, 64).ToArray();

        string firstToken = utility.GenerateAccessToken(refreshToken, "web-key");
        string secondToken = utility.GenerateAccessToken(refreshToken, "web-key");

        firstToken.ShouldNotBe(secondToken);
        AccessTokenHashUtility.Hash(firstToken).ShouldNotBe(AccessTokenHashUtility.Hash(secondToken));
    }

    [Fact]
    public async Task Generated_access_token_validates_with_matching_refresh_token()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)12, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(token, refreshToken, now, now.Plus(Duration.FromMinutes(20)), JsonWebTokenPurpose.Active, Duration.FromMinutes(10));
        status.ShouldBe(IntraMessage.TOKEN_PASSED_VALIDATION);
        webKey.ShouldBe("web-key");
    }

    [Fact]
    public async Task ValidateAccessToken_returns_refreshable_status_inside_refresh_window()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)17, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(token, refreshToken, now, now.Plus(Duration.FromMinutes(5)), JsonWebTokenPurpose.Active, Duration.FromMinutes(10));

        status.ShouldBe(IntraMessage.TOKEN_AT_EXPIRATION);
        webKey.ShouldBe("web-key");
    }

    [Fact]
    public async Task ValidateAccessToken_returns_expired_status_after_expiration()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)18, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        string token = utility.GenerateAccessToken(refreshToken, "web-key");

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(token, refreshToken, now, now.Minus(Duration.FromSeconds(1)), JsonWebTokenPurpose.Active, Duration.FromMinutes(10));

        status.ShouldBe(IntraMessage.TOKEN_EXPIRED_VALIDATION);
        webKey.ShouldBe("web-key");
    }

    [Fact]
    public void GenerateAccessToken_includes_the_requested_token_purpose()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)13, 64).ToArray();

        string token = utility.GenerateAccessToken(refreshToken, "web-key", JsonWebTokenPurpose.PreAuthTwoFactor);

        var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        parsedToken.Claims.Single(claim => claim.Type == JsonWebTokenPurpose.ClaimType).Value.ShouldBe(JsonWebTokenPurpose.PreAuthTwoFactor);
    }

    [Fact]
    public async Task ValidateAccessToken_rejects_tokens_with_the_wrong_purpose()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)14, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        string activeToken = utility.GenerateAccessToken(refreshToken, "web-key", JsonWebTokenPurpose.Active);

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(
            activeToken,
            refreshToken,
            now,
            now.Plus(Duration.FromMinutes(5)),
            JsonWebTokenPurpose.PreAuthTwoFactor);

        status.ShouldBe(IntraMessage.TOKEN_FAILED_VALIDATION);
        webKey.ShouldBeNull();
    }

    [Fact]
    public async Task ValidateAccessToken_accepts_matching_pre_auth_purpose()
    {
        var utility = Utility();
        byte[] refreshToken = Enumerable.Repeat((byte)15, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        string preAuthToken = utility.GenerateAccessToken(refreshToken, "web-key", JsonWebTokenPurpose.PreAuthTwoFactor);

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(
            preAuthToken,
            refreshToken,
            now,
            now.Plus(Duration.FromMinutes(5)),
            JsonWebTokenPurpose.PreAuthTwoFactor);

        status.ShouldBe(IntraMessage.TOKEN_PASSED_VALIDATION);
        webKey.ShouldBe("web-key");
    }

    [Fact]
    public async Task ValidateAccessToken_rejects_tokens_missing_jti()
    {
        var settings = Options.Create(TestJwtSettings());
        var utility = new JsonWebTokenUtility(Substitute.For<ILogger<JsonWebTokenUtility>>(), settings);
        byte[] refreshToken = Enumerable.Repeat((byte)19, 64).ToArray();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        string token = BuildTokenWithoutJti(refreshToken, "web-key", JsonWebTokenPurpose.Active, settings.Value.JsonWebTokenIssuer);

        (IntraMessage status, string? webKey) = await utility.ValidateAccessToken(token, refreshToken, now, now.Plus(Duration.FromMinutes(5)));

        status.ShouldBe(IntraMessage.TOKEN_VALIDATION_MALFORMED);
        webKey.ShouldBeNull();
    }


    [Fact]
    public void Json_web_token_validation_log_reasons_are_stable_and_bounded()
    {
        string[] reasons =
        [
            JsonWebTokenValidationLogReasons.TokenHandlerRejected,
            JsonWebTokenValidationLogReasons.MissingRequiredClaims,
            JsonWebTokenValidationLogReasons.PurposeMismatch,
            JsonWebTokenValidationLogReasons.SecurityTokenException,
            JsonWebTokenValidationLogReasons.UnexpectedException
        ];

        reasons.ShouldContain("JWT_TOKEN_HANDLER_REJECTED");
        reasons.ShouldContain("JWT_MISSING_REQUIRED_CLAIMS");
        reasons.ShouldContain("JWT_PURPOSE_MISMATCH");
        reasons.ShouldContain("JWT_SECURITY_TOKEN_EXCEPTION");
        reasons.ShouldContain("JWT_UNEXPECTED_VALIDATION_EXCEPTION");
        reasons.Distinct(StringComparer.Ordinal).Count().ShouldBe(reasons.Length);
        reasons.ShouldAllBe(reason => reason.StartsWith("JWT_", StringComparison.Ordinal));
    }

    [Fact]
    public void Json_web_token_validation_logging_does_not_emit_exception_messages_or_stack_traces()
    {
        string source = File.ReadAllText(ProjectFile("Rigging", "Authentication", "JsonWebTokenUtility.cs"));

        source.ShouldContain("ReasonCode");
        source.ShouldContain("ExceptionType");
        source.ShouldContain("SafeExceptionType");
        source.ShouldNotContain("{Message}");
        source.ShouldNotContain("{StackTrace}");
        source.ShouldNotContain(".Message");
        source.ShouldNotContain(".StackTrace");
        source.ShouldNotContain("LogInformation(ex");
        source.ShouldNotContain("LogWarning(ex");
        source.ShouldNotContain("LogError(ex");
    }

    [Fact]
    public void Json_web_token_validation_logging_uses_reason_codes_for_expected_invalid_paths()
    {
        string source = File.ReadAllText(ProjectFile("Rigging", "Authentication", "JsonWebTokenUtility.cs"));

        source.ShouldContain("JsonWebTokenValidationLogReasons.TokenHandlerRejected");
        source.ShouldContain("JsonWebTokenValidationLogReasons.MissingRequiredClaims");
        source.ShouldContain("JsonWebTokenValidationLogReasons.PurposeMismatch");
        source.ShouldContain("JsonWebTokenValidationLogReasons.SecurityTokenException");
        source.ShouldContain("JsonWebTokenValidationLogReasons.UnexpectedException");
        source.ShouldContain("Access token validation failed closed with reason {ReasonCode} and exception type {ExceptionType}.");
    }

    private static JsonWebTokenUtility Utility()
    {
        return new JsonWebTokenUtility(Substitute.For<ILogger<JsonWebTokenUtility>>(), Options.Create(TestJwtSettings()));
    }

    private static JWTSettings TestJwtSettings()
    {
        return new JWTSettings
        {
            JsonWebTokenIssuer = "treehammock-tests",
            RefreshTokenAliveDays = 0,
            RefreshTokenAliveHours = 0,
            RefreshTokenAliveMinutes = 30,
            RefreshTokenAliveDays_2FA = 0,
            RefreshTokenAliveHours_2FA = 0,
            RefreshTokenAliveMinutes_2FA = 2,
            RefreshTokenAliveDays_DB = 7,
            RefreshTokenAliveHours_DB = 0,
            RefreshTokenAliveMinutes_DB = 0,
            RefreshTokenAliveDays_Short = 0,
            RefreshTokenAliveHours_Short = 15,
            RefreshTokenAliveMinutes_Short = 0,
            RefreshTokenBytes = 64,
        };
    }

    private static string BuildTokenWithoutJti(byte[] refreshToken, string webKey, string purpose, string issuer)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JsonWebTokenPurpose.WebKeyClaimType, webKey),
                new Claim(JsonWebTokenPurpose.ClaimType, purpose),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            }),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(refreshToken), SecurityAlgorithms.HmacSha256)
        };

        return tokenHandler.WriteToken(tokenHandler.CreateToken(descriptor));
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
