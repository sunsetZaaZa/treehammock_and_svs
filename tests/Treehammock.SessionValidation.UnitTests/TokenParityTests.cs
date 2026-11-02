using NodaTime;
using Treehammock.SessionValidation.Core;
using Xunit;
using Legacy = Svs02.FrozenBaseline;

namespace Treehammock.SessionValidation.UnitTests;

public sealed class TokenParityTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (string name in new[] { "valid", "missing-webkey", "empty-webkey", "missing-purpose", "empty-purpose",
            "missing-jti", "empty-jti", "preauth", "wrong-purpose", "wrong-key", "wrong-issuer", "hs384", "hs512",
            "unsigned", "malformed", "empty", "opaque-refresh", "expired-jwt-claim", "access-equality", "access-expired",
            "window-before", "window-at-start", "window-inside", "negative-window", "preauth-expected", "arithmetic-overflow" })
            yield return new object[] { name };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Extracted_verifier_matches_frozen_original_field_by_field(string name)
    {
        var logger = new Legacy.RecordingLogger<Legacy.JsonWebTokenUtility>();
        var legacy = new Legacy.JsonWebTokenUtility(logger, new Legacy.Options<Legacy.JWTSettings>(new()));
        var verifier = new TreehammockTokenVerifier();
        Instant now = TestSessions.Now, expiry = now + Duration.FromMinutes(5);
        Duration? window = null;
        string purpose = TreehammockTokenPurpose.Active;
        string token = name switch
        {
            "malformed" => "not.a.valid.jws", "empty" => "", "opaque-refresh" => Convert.ToBase64String(new byte[32]),
            "preauth-expected" => TestSessions.Mint("preauth"), _ => TestSessions.Mint(name)
        };
        if (name == "access-equality") expiry = now;
        if (name == "access-expired") expiry = now - Duration.FromSeconds(1);
        if (name.StartsWith("window-", StringComparison.Ordinal))
        {
            window = Duration.FromMinutes(10);
            expiry = now + Duration.FromMinutes(name == "window-before" ? 11 : name == "window-at-start" ? 10 : 5);
        }
        if (name == "negative-window") window = Duration.FromMinutes(-10);
        if (name == "preauth-expected") purpose = TreehammockTokenPurpose.PreAuthTwoFactor;
        if (name == "arithmetic-overflow") { expiry = Instant.MinValue; window = Duration.FromSeconds(1); }

        var old = await legacy.ValidateAccessToken(token, TestSessions.Key(), now, expiry, purpose, window);
        var actual = await verifier.ValidateAsync(token, TestSessions.Key(), TestSessions.Issuer, now, expiry, purpose, window);
        Assert.Equal(Map(old.Item1), actual.Status);
        Assert.Equal(old.Item2, actual.WebKey);
        Assert.Equal(logger.Reason, Reason(actual.Reason));
        Assert.Equal(logger.ExceptionType, actual.ExceptionType);

        TokenStatus expected = name switch
        {
            "missing-webkey" or "empty-webkey" or "missing-purpose" or "empty-purpose" or "missing-jti" or "empty-jti" => TokenStatus.Malformed,
            "preauth" or "wrong-purpose" or "wrong-key" or "wrong-issuer" or "hs384" or "hs512" or "unsigned" or "malformed" or "empty" or "opaque-refresh" => TokenStatus.Failed,
            "access-equality" or "access-expired" => TokenStatus.Expired,
            "window-at-start" or "window-inside" => TokenStatus.AtExpiration,
            "arithmetic-overflow" => TokenStatus.UnexpectedException,
            _ => TokenStatus.Passed
        };
        Assert.Equal(expected, actual.Status);
    }

    [Fact]
    public async Task Invalid_server_key_retains_existing_exception_boundary()
    {
        var legacy = new Legacy.JsonWebTokenUtility(new Legacy.RecordingLogger<Legacy.JsonWebTokenUtility>(), new Legacy.Options<Legacy.JWTSettings>(new()));
        var old = await Record.ExceptionAsync(() => legacy.ValidateAccessToken(TestSessions.Mint(), null!, TestSessions.Now, TestSessions.Now));
        var actual = await Record.ExceptionAsync(() => new TreehammockTokenVerifier().ValidateAsync(TestSessions.Mint(), null!, TestSessions.Issuer, TestSessions.Now, TestSessions.Now));
        Assert.NotNull(old); Assert.NotNull(actual); Assert.Equal(old.GetType(), actual.GetType());
    }

    private static TokenStatus Map(Legacy.IntraMessage status) => status switch
    {
        Legacy.IntraMessage.TOKEN_PASSED_VALIDATION => TokenStatus.Passed,
        Legacy.IntraMessage.TOKEN_AT_EXPIRATION => TokenStatus.AtExpiration,
        Legacy.IntraMessage.TOKEN_EXPIRED_VALIDATION => TokenStatus.Expired,
        Legacy.IntraMessage.TOKEN_VALIDATION_MALFORMED => TokenStatus.Malformed,
        Legacy.IntraMessage.TOKEN_THREW_EXCEPTION_IN_VALIDATION => TokenStatus.UnexpectedException,
        _ => TokenStatus.Failed
    };
    private static string? Reason(TokenFailureReason reason) => reason switch
    {
        TokenFailureReason.TokenHandlerRejected => "JWT_TOKEN_HANDLER_REJECTED",
        TokenFailureReason.MissingRequiredClaims => "JWT_MISSING_REQUIRED_CLAIMS",
        TokenFailureReason.PurposeMismatch => "JWT_PURPOSE_MISMATCH",
        TokenFailureReason.SecurityTokenException => "JWT_SECURITY_TOKEN_EXCEPTION",
        TokenFailureReason.UnexpectedException => "JWT_UNEXPECTED_VALIDATION_EXCEPTION",
        _ => null
    };
}
