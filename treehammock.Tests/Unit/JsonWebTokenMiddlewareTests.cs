using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class JsonWebTokenMiddlewareTests
{
    [Theory]
    [InlineData("access")]
    [InlineData("hard")]
    [InlineData("cutoff")]
    [InlineData("account")]
    [InlineData("family")]
    [InlineData("generation")]
    [InlineData("stamp")]
    [InlineData("security")]
    [InlineData("live")]
    public async Task Final_entitlement_reload_cannot_publish_expired_or_rebound_session(string boundary)
    {
        var stored=StoredSession();int reads=0;
        var cache=Substitute.For<IActiveUserCacheService>();var repo=Substitute.For<ISessionRepo>();var jwt=Substitute.For<IJsonWebTokenUtility>();
        cache.GetSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns((ActiveSession?)null);
        cache.SetSession(Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<TimeSpan>(),Arg.Any<CommandFlags>(),Arg.Any<CancellationToken>()).Returns(async call=>
        {
            await Task.Yield();
            var active=call.ArgAt<ActiveSession>(1);
            // Cross the projection boundary while the cache await is in flight.
            active.entitlements=active.entitlements! with {NextBoundary=SystemClock.Instance.GetCurrentInstant()};
            return true;
        });
        repo.GetSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(async call=>
        {
            if(++reads==1)return stored;
            await Task.Yield();var fresh=SessionProtocol.FromSession(stored).toSession();var now=SystemClock.Instance.GetCurrentInstant();
            if(boundary=="access")fresh.accessExpiration=now;
            if(boundary=="hard"){fresh.sessionExpiration=now;fresh.accessExpiration=now;}
            if(boundary=="cutoff")fresh.cutOff=now;
            if(boundary=="account")fresh.accountId=Guid.NewGuid();
            if(boundary=="family")fresh.familyId=Guid.NewGuid();
            if(boundary=="generation")fresh.generation++;
            if(boundary=="stamp")fresh.accountSecurityStamp=Guid.NewGuid();
            if(boundary=="security")fresh.securityStamp=Guid.NewGuid();
            fresh.entitlements=treehammock.Tests.Support.EntitlementTestData.ForAccount(fresh.accountId);
            return fresh;
        });
        jwt.ValidateAccessToken("late-access",Arg.Any<byte[]>(),Arg.Any<Instant>(),Arg.Any<Instant>(),JsonWebTokenPurpose.Active,Arg.Any<Duration?>()).Returns((IntraMessage.TOKEN_PASSED_VALIDATION,(string?)"web"));
        var context=new DefaultHttpContext();context.RequestAborted=TestContext.Current.CancellationToken;context.Request.Headers["AccessToken"]="late-access";
        await new JsonWebTokenMiddleware(_=>Task.CompletedTask).InvokeAsync(context,cache,jwt,repo,Options.Create(TestJwtSettings()));
        reads.ShouldBe(2);
        if(boundary=="live")context.Items[AuthContextItems.ActiveSession].ShouldNotBeNull();
        else
        {
            context.Items[AuthContextItems.ActiveSession].ShouldBeNull();context.Items[AuthContextItems.WebKey].ShouldBeNull();context.Items[AuthContextItems.HashedAccessToken].ShouldBeNull();
            context.Response.Headers[SessionProtocol.FamilyHeader].ToString().ShouldBeEmpty();
            context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        }
    }

    [Fact]
    public async Task InvokeAsync_without_access_token_calls_next_once_and_leaves_context_unauthenticated()
    {
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBeNull();
        context.Items[AuthContextItems.ActiveSession].ShouldBeNull();
        _ = activeUsers.DidNotReceiveWithAnyArgs().GetSession(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().GetSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_with_valid_cached_session_sets_context_items_and_calls_next_once()
    {
        const string accessToken = "cached-access-token";
        const string webKey = "web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldNotBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(AccessTokenHashUtility.Hash(accessToken));
        ReferenceEquals(context.Items[AuthContextItems.ActiveSession], session).ShouldBeTrue();
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().GetSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Theory]
    [InlineData(CachedSessionTrustStatus.SessionNotFound)]
    [InlineData(CachedSessionTrustStatus.AccountNotFound)]
    [InlineData(CachedSessionTrustStatus.SecurityStampMismatch)]
    [InlineData(CachedSessionTrustStatus.AccountSecurityStampMismatch)]
    public async Task InvokeAsync_with_stale_cached_session_clears_token_without_authenticating(CachedSessionTrustStatus staleStatus)
    {
        const string accessToken = "stale-cached-access-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(staleStatus, session.accessExpiration, session.sessionExpiration, session.cutOff, Guid.NewGuid(), session.accountSecurityStamp)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_cutoff_update_clears_token_without_authenticating()
    {
        const string accessToken = "cutoff-updated-cached-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(
            expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(30)));
        Instant databaseCutOff = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, databaseCutOff, session.securityStamp, session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_uses_database_access_expiration_before_jwt_validation()
    {
        const string accessToken = "cached-token-db-shortened-access";
        const string webKey = "db-shortened-access-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseAccessExpiration = now.Plus(Duration.FromMinutes(5));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.Valid,
                databaseAccessExpiration,
                session.sessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "VALID", Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), databaseAccessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        session.accessExpiration.ShouldBe(databaseAccessExpiration);
        await jwtUtils.Received(1).ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), databaseAccessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
        await activeUsers.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(cached => cached.accessExpiration == databaseAccessExpiration),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_access_expiration_expired_clears_token_without_authenticating()
    {
        const string accessToken = "cached-token-db-expired-access";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseAccessExpiration = now.Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.SessionExpired,
                databaseAccessExpiration,
                session.sessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "SESSION_EXPIRED")));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_session_expiration_expired_clears_token_without_authenticating()
    {
        const string accessToken = "cached-token-db-expired-session";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseSessionExpiration = now.Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.SessionExpired,
                session.accessExpiration,
                databaseSessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "SESSION_EXPIRED")));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cutoff_expired_cached_session_clears_token_without_authenticating()
    {
        const string accessToken = "cutoff-expired-cached-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(
            expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = sessionRepo.DidNotReceive().ExpireSession(expectedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_with_cutoff_expired_database_session_clears_token_without_cache_rehydrate()
    {
        const string accessToken = "cutoff-expired-database-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var storedSession = StoredSession(
            accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = sessionRepo.DidNotReceive().ExpireSession(expectedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_misses_uses_database_session_before_validation()
    {
        const string accessToken = "database-backed-token";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        ActiveSession authenticatedSession = context.Items[AuthContextItems.ActiveSession].ShouldBeOfType<ActiveSession>();
        authenticatedSession.accountId.ShouldBe(storedSession.accountId);
        authenticatedSession.accountSecurityStamp.ShouldBe(storedSession.accountSecurityStamp);
        await sessionRepo.Received(1).GetSession(AccessTokenHashUtility.Hash(accessToken), cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration == storedSession.accessExpiration &&
                session.sessionExpiration == storedSession.sessionExpiration),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_misses_uses_database_access_expiration_not_hard_session_expiration()
    {
        const string accessToken = "database-backed-split-expiration-token";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant accessExpiration = now.Plus(Duration.FromMinutes(5));
        Instant sessionExpiration = now.Plus(Duration.FromDays(7));
        var storedSession = StoredSession(accessExpiration: accessExpiration, sessionExpiration: sessionExpiration);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["webKey"].ShouldBe(webKey);
        await jwtUtils.Received(1).ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration == accessExpiration &&
                session.sessionExpiration == sessionExpiration),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_database_access_expiration_is_expired_rejects_even_when_hard_session_is_valid()
    {
        const string accessToken = "database-backed-expired-access-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant accessExpiration = now.Minus(Duration.FromMinutes(1));
        Instant sessionExpiration = now.Plus(Duration.FromDays(7));
        var storedSession = StoredSession(accessExpiration: accessExpiration, sessionExpiration: sessionExpiration);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_EXPIRED_VALIDATION, (string?)null)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        _ = jwtUtils.DidNotReceive().ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_is_missing_calls_next_without_validation()
    {
        const string accessToken = "missing-database-session-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(AccessTokenHashUtility.Hash(accessToken), cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_fully_expired_token_does_not_refresh_and_tells_client_to_clear_token()
    {
        const string accessToken = "already-expired-token";
        const string webKey = "expired-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_EXPIRED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_is_used_rehydrates_cache_with_features_and_cutoff()
    {
        const string accessToken = "database-backed-token-with-metadata";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        Instant cutOff = createdOn.Plus(Duration.FromMinutes(20));
        var storedSession = treehammock.Tests.Support.EntitlementTestData.Attach(new Session(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)7, 64).ToArray(),
            0,
            3,
            createdOn,
            Period.FromMinutes(30),
            createdOn.Plus(Duration.FromMinutes(10)),
            createdOn.Plus(Duration.FromMinutes(25)),
            cutOff,
            FeatureSet.premium,
            accountSecurityStamp: Guid.Parse("77777777-8888-9999-aaaa-bbbbbbbbbbbb")));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.cutOff == cutOff &&
                session.features == FeatureSet.premium &&
                session.features == FeatureSet.premium),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task InvokeAsync_when_active_cache_payload_is_stale_revokes_cache_and_uses_database_session()
    {
        const string accessToken = "stale-active-cache-db-backed-token";
        const string webKey = "db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<ActiveSession?>(new StaleActiveSessionCachePayloadException("legacy active payload")));
        activeUsers.RevokeSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_active_cache_payload_is_stale_and_database_misses_revokes_cache_and_leaves_request_unauthenticated()
    {
        const string accessToken = "stale-active-cache-db-misses-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<ActiveSession?>(new StaleActiveSessionCachePayloadException("legacy active payload")));
        activeUsers.RevokeSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_throws_uses_database_session_before_validation()
    {
        const string accessToken = "cache-read-fails-db-backed-token";
        const string webKey = "db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<ActiveSession?>(new InvalidOperationException("redis read failed")));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_throws_and_database_misses_leaves_request_unauthenticated()
    {
        const string accessToken = "cache-read-fails-db-misses-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<ActiveSession?>(new InvalidOperationException("redis read failed")));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_throws_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-throws-db-backed-token";
        const string webKey = "db-backed-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("redis write failed")));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_returns_false_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-false-db-backed-token";
        const string webKey = "db-backed-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task InvokeAsync_when_cache_read_times_out_uses_database_session_before_validation()
    {
        const string accessToken = "cache-read-timeout-db-backed-token";
        const string webKey = "timeout-db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var fallbackSettings = TestFallbackSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var cacheRead = new TaskCompletionSource<ActiveSession?>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(cacheRead.Task);
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings), Options.Create(fallbackSettings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(expectedHash);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_times_out_and_database_times_out_denies_without_jwt_validation()
    {
        const string accessToken = "cache-read-timeout-db-timeout-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var fallbackSettings = TestFallbackSettings();
        var cacheRead = new TaskCompletionSource<ActiveSession?>();
        var dbRead = new TaskCompletionSource<Session?>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(cacheRead.Task);
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(dbRead.Task);
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await new treehammock.Rigging.Dependencies.DependencyExceptionMiddleware(
            _ => middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()), Options.Create(fallbackSettings)), Microsoft.Extensions.Logging.Abstractions.NullLogger<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>.Instance).InvokeAsync(context);

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(0);
        context.Response.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_cached_session_trust_validation_times_out_denies_without_jwt_validation()
    {
        const string accessToken = "cached-session-trust-timeout-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var fallbackSettings = TestFallbackSettings();
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var trustCheck = new TaskCompletionSource<CachedSessionTrustResult?>();
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(trustCheck.Task);
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await new treehammock.Rigging.Dependencies.DependencyExceptionMiddleware(
            _ => middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()), Options.Create(fallbackSettings)), Microsoft.Extensions.Logging.Abstractions.NullLogger<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>.Instance).InvokeAsync(context);

        nextCalls.ShouldBe(0);
        context.Response.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        context.Items[AuthContextItems.ActiveSession].ShouldBeNull();
        _ = activeUsers.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_times_out_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-timeout-db-backed-token";
        const string webKey = "db-backed-timeout-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var fallbackSettings = TestFallbackSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var cacheWrite = new TaskCompletionSource<bool>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(cacheWrite.Task);
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings), Options.Create(fallbackSettings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(expectedHash);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cor03_database_fault_denies_warm_and_cold_cache_without_clearing_token(bool warm)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = "still-valid-token";
        var cache = Substitute.For<IActiveUserCacheService>();
        var repo = Substitute.For<ISessionRepo>();
        var jwt = Substitute.For<IJsonWebTokenUtility>();
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        cache.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(warm ? session : null));
        repo.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(_ => Task.FromException<Session?>(new InvalidOperationException("sql unavailable")));
        repo.ValidateCachedSessionTrust(Arg.Any<string>(), Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<CachedSessionTrustResult?>(new InvalidOperationException("sql unavailable")));
        int next = 0;
        var middleware = new JsonWebTokenMiddleware(_ => { next++; return Task.CompletedTask; });
        await new treehammock.Rigging.Dependencies.DependencyExceptionMiddleware(
            _ => middleware.InvokeAsync(context, cache, jwt, repo, Options.Create(TestJwtSettings())),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>.Instance).InvokeAsync(context);
        context.Response.StatusCode.ShouldBe(503);
        context.Response.Headers["AppStatus"].ToString().ShouldBeEmpty();
        context.Response.Headers["AccessToken"].ToString().ShouldBeEmpty();
        next.ShouldBe(0);
        await cache.DidNotReceiveWithAnyArgs().RevokeSession(default!, default);
        await jwt.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default, default);
    }

    [Fact]
    public async Task Cor03_database_deadline_reaches_native_lookup_token()
    {
        var context = new DefaultHttpContext(); context.Request.Headers["AccessToken"] = "deadline-token";
        var repo = Substitute.For<ISessionRepo>();
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        repo.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(async call =>
        {
            var token = call.ArgAt<CancellationToken>(1);
            try { await Task.Delay(Timeout.Infinite, token); return (Session?)null; }
            finally { if (token.IsCancellationRequested) canceled.TrySetResult(); }
        });
        var middleware = new JsonWebTokenMiddleware(_ => Task.CompletedTask);
        await new treehammock.Rigging.Dependencies.DependencyExceptionMiddleware(
            _ => middleware.InvokeAsync(context, Substitute.For<IActiveUserCacheService>(), Substitute.For<IJsonWebTokenUtility>(), repo,
                Options.Create(TestJwtSettings()), Options.Create(new SessionCacheFallbackSettings { DatabaseFallbackTimeoutMilliseconds = 25 })),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>.Instance).InvokeAsync(context);
        await canceled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        context.Response.StatusCode.ShouldBe(503);
        context.Response.Headers["AppStatus"].ToString().ShouldBeEmpty();
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
            RefreshTokenAliveHours_Short = 0,
            RefreshTokenAliveMinutes_Short = 15,
            RefreshTokenBytes = 64,
        };
    }


    private static SessionCacheFallbackSettings TestFallbackSettings()
    {
        return new SessionCacheFallbackSettings
        {
            CacheReadTimeoutMilliseconds = 10,
            CacheWriteTimeoutMilliseconds = 10,
            CacheRevokeTimeoutMilliseconds = 10,
            DatabaseFallbackTimeoutMilliseconds = 10
        };
    }

    private static ActiveSession ActiveSession(
        short refreshes = 0,
        Instant? expiration = null,
        Instant? cutOff = null,
        Instant? createdOn = null,
        Period? sessionLifespan = null)
    {
        Instant sessionCreatedOn = createdOn ?? SystemClock.Instance.GetCurrentInstant();
        Period hardSessionLifespan = sessionLifespan ?? Period.FromMinutes(30);
        Instant hardSessionExpiration = sessionCreatedOn.Plus(hardSessionLifespan.ToDuration());
        return treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)9, 64).ToArray(),
            refreshes,
            sessionCreatedOn,
            hardSessionLifespan,
            expiration ?? sessionCreatedOn.Plus(Duration.FromMinutes(30)),
            hardSessionExpiration,
            cutOff,
            FeatureSet.basic,
            accountSecurityStamp: Guid.Parse("88888888-9999-aaaa-bbbb-cccccccccccc")));
    }

    private static Session StoredSession(Instant? accessExpiration = null, Instant? sessionExpiration = null, Instant? cutOff = null)
    {
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        return treehammock.Tests.Support.EntitlementTestData.Attach(new Session(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)8, 64).ToArray(),
            0,
            3,
            createdOn,
            Period.FromMinutes(30),
            accessExpiration ?? createdOn.Plus(Duration.FromMinutes(10)),
            sessionExpiration ?? createdOn.Plus(Duration.FromMinutes(30)),
            cutOff,
            accountSecurityStamp: Guid.Parse("99999999-aaaa-bbbb-cccc-dddddddddddd")));
    }
}
