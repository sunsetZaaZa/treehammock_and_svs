using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Treehammock.SessionValidation.Core;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Support;

namespace treehammock.Tests.Unit;

public sealed class SharedSessionPolicyAdapterTests
{
    [Theory]
    [InlineData(TokenStatus.Passed, IntraMessage.TOKEN_PASSED_VALIDATION)]
    [InlineData(TokenStatus.AtExpiration, IntraMessage.TOKEN_AT_EXPIRATION)]
    [InlineData(TokenStatus.Expired, IntraMessage.TOKEN_EXPIRED_VALIDATION)]
    [InlineData(TokenStatus.Malformed, IntraMessage.TOKEN_VALIDATION_MALFORMED)]
    [InlineData(TokenStatus.Failed, IntraMessage.TOKEN_FAILED_VALIDATION)]
    [InlineData(TokenStatus.UnexpectedException, IntraMessage.TOKEN_THREW_EXCEPTION_IN_VALIDATION)]
    public async Task Legacy_utility_delegates_exact_inputs_and_preserves_status_mapping(TokenStatus status, IntraMessage expected)
    {
        var tokens = Substitute.For<ITreehammockTokenVerifier>();
        var now = Instant.FromUtc(2026, 10, 17, 1, 0); var expiry = now + Duration.FromMinutes(5); byte[] key = new byte[64];
        tokens.ValidateAsync("synthetic-token", key, "issuer.test", now, expiry, JsonWebTokenPurpose.PreAuthTwoFactor, Duration.FromMinutes(1))
            .Returns(new TokenVerificationResult(status, "synthetic-web"));
        var utility = new JsonWebTokenUtility(NullLogger<JsonWebTokenUtility>.Instance,
            Options.Create(new JWTSettings { JsonWebTokenIssuer = "issuer.test" }), tokens);
        var actual = await utility.ValidateAccessToken("synthetic-token", key, now, expiry, JsonWebTokenPurpose.PreAuthTwoFactor, Duration.FromMinutes(1));
        Assert.Equal(expected, actual.Item1); Assert.Equal("synthetic-web", actual.Item2);
        await tokens.Received(1).ValidateAsync("synthetic-token", key, "issuer.test", now, expiry, JsonWebTokenPurpose.PreAuthTwoFactor, Duration.FromMinutes(1));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Middleware_uses_shared_lifetime_after_existing_DB_trust_and_preserves_public_context(bool allow)
    {
        var now = SystemClock.Instance.GetCurrentInstant();
        var session = new ActiveSession(Guid.NewGuid(), new byte[64], 0, now, Period.FromHours(1),
            now + Duration.FromMinutes(10), now + Duration.FromHours(1), null, FeatureSet.basic, accountSecurityStamp: Guid.NewGuid());
        session.entitlements = EntitlementTestData.ForAccount(session.accountId, evaluated: now - Duration.FromSeconds(1));
        var cache = Substitute.For<IActiveUserCacheService>(); var db = Substitute.For<ISessionRepo>(); var jwt = Substitute.For<IJsonWebTokenUtility>();
        var policy = Substitute.For<ITreehammockSessionPolicyEvaluator>();
        policy.IsLifetimeCurrent(Arg.Any<SessionLifetime>(), Arg.Any<Instant>()).Returns(allow);
        cache.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(session);
        db.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp, Arg.Any<CancellationToken>())
            .Returns(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration,
                null, session.securityStamp, session.accountSecurityStamp, FamilyId: session.familyId, Generation: session.generation,
                ProtocolVersion: session.protocolVersion, Entitlements: session.entitlements));
        jwt.ValidateAccessToken("test-access", session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Duration.Zero)
            .Returns((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)"web"));
        var context = new DefaultHttpContext(); context.Request.Headers["Authorization"] = "Bearer test-access";
        int next = 0;
        await new JsonWebTokenMiddleware(_ => { next++; return Task.CompletedTask; }, policy: policy)
            .InvokeAsync(context, cache, jwt, db, Options.Create(new JWTSettings { RefreshTokenAliveMinutes = 10 }));
        Assert.Equal(1, next);
        await db.Received(1).ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp, Arg.Any<CancellationToken>());
        policy.Received().IsLifetimeCurrent(new SessionLifetime(session.accessExpiration, session.sessionExpiration, session.cutOff), Arg.Any<Instant>());
        if (allow)
        {
            Assert.Same(session, context.Items[AuthContextItems.ActiveSession]); Assert.Equal("web", context.Items[AuthContextItems.WebKey]);
            Assert.Equal("2", context.Response.Headers[SessionProtocol.VersionHeader].ToString());
        }
        else
        {
            Assert.Null(context.Items[AuthContextItems.ActiveSession]); Assert.Null(context.Items[AuthContextItems.WebKey]);
            Assert.Equal(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString(), context.Response.Headers["AppStatus"].ToString());
            _ = jwt.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
        }
    }

    [Fact]
    public void Protocol_and_purpose_constants_are_shared_without_changing_wire_values()
    {
        Assert.Equal(2, SessionProtocol.Version); Assert.Equal(SessionIdentity.MaximumGeneration, SessionProtocol.MaximumGeneration);
        Assert.Equal(TreehammockTokenPurpose.Active, JsonWebTokenPurpose.Active);
        Assert.Equal(TreehammockTokenPurpose.PreAuthTwoFactor, JsonWebTokenPurpose.PreAuthTwoFactor);
        Assert.Equal("purpose", JsonWebTokenPurpose.ClaimType); Assert.Equal("webKey", JsonWebTokenPurpose.WebKeyClaimType);
    }
}
